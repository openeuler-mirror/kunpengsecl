package daemontools

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

const (
	LOG_FILE             = "./qca_daemon.log"
	SELF_CGROUP_FILE     = "/proc/self/cgroup"
	DMI_PRODUCT_UUID     = "/sys/class/dmi/id/product_uuid"
	DMI_PRODUCT_NAME     = "/sys/class/dmi/id/product_name"
	KVM_NAME             = "KVM Virtual Machine"
	NOT_DOCKER_CONTAINER = "not docker container"
	MAX_INPUT_SIZE       = 0x3000
)

var (
	ValidDockerId = regexp.MustCompile(`1:name=systemd:/docker/([a-z0-9]{64})`)
	Info          *log.Logger
	Error         *log.Logger

	// cmd flags
	HostServer *string
)

// before main
func init() {
	logFile, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Open log file %v faild, %v", LOG_FILE, err)
	}

	log.SetOutput(io.MultiWriter(logFile, os.Stdout))
}

func InitFlags() {
	HostServer = pflag.StringP("hostserver", "H", "", "host server addr ip:port")
	pflag.Parse()
}

func readFile(file string) (string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read file failed, %v", err)
	}
	return string(content), nil
}

func getSelfDockerId() (string, error) {
	con, err := readFile(SELF_CGROUP_FILE)
	if err != nil {
		return "", err
	}
	match := ValidDockerId.FindStringSubmatch(string(con))
	if len(match) == 2 {
		return match[1], nil
	}
	return "", fmt.Errorf(NOT_DOCKER_CONTAINER)
}

// get kvm id
func getSelfKvmId() (string, error) {
	uuidstr, err := readFile(DMI_PRODUCT_UUID)
	if err != nil {
		return "", fmt.Errorf("read kvm uuid failed, %v", err)
	}
	uuidstr = strings.Trim(uuidstr, "\n ")
	_, err = uuid.Parse(uuidstr)
	if err != nil {
		return "", fmt.Errorf("uuid is invalid, %v", err)
	}

	return uuidstr, nil
}

func GetVirtualClientInfo() (*qcatools.VirtualGuestInfo, error) {
	con, err := readFile(DMI_PRODUCT_NAME)
	if err != nil {
		return nil, fmt.Errorf("read kvm name failed, %v", err)
	}
	con = strings.Trim(con, "\n ")

	// kvm container
	if con == KVM_NAME {
		id, err := getSelfKvmId()
		if err != nil {
			return nil, fmt.Errorf("get kvm id failed, %v", err)
		}
		return &qcatools.VirtualGuestInfo{
			Id:   id,
			Type: "kvm",
		}, nil
	}

	dockerId, err := getSelfDockerId()
	if err == nil {
		return &qcatools.VirtualGuestInfo{
			Id:   dockerId,
			Type: "docker",
		}, nil
	}

	return nil, err
}

func StartClientConn(saddr string, info *qcatools.VirtualGuestInfo) {
	conn, err := net.Dial("tcp", saddr)
	if err != nil {
		log.Fatalf("Connect to server %v failed, %v\n", saddr, err)
	}
	defer conn.Close()
	log.Printf("Connect to server %v success\n", saddr)

	if err = qcatools.SendData(conn, info, qcatools.RET_SUCCESS); err != nil {
		log.Fatalf("Send register info to ra_server failed, %v", err)
	}

	var ret []byte
	if err = qcatools.RecvData(conn, &ret); err != nil {
		log.Fatalf("Read register reply failed, %v", err)
	}
	log.Println("Register client info success\n")

	var retVal int
	for {
		reportIn := []byte{}
		if err = qcatools.RecvData(conn, &reportIn); err != nil {
			log.Fatalf("Read ra_server forward request data failed, %v", err)
		}
		log.Println("Get host forward report request")

		retVal = qcatools.RET_SUCCESS
		report, err := qcatools.CallCRemoteAttest(reportIn, qcatools.MAX_OUTBUF_SIZE)
		if err != nil {
			log.Printf("Get report from libqca-report failed, %v", err)
			retVal = qcatools.RET_CALLCERR
			report = []byte("Get report by qta_report failed")
		} else {
			log.Println("Get TA report success")
		}

		if err = qcatools.SendData(conn, report, retVal); err != nil {
			log.Fatalf("Send register info to ra_server failed, %v", err)
		}

	}
}
