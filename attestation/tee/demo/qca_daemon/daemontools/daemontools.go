package daemontools

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

const (
	// get docker id
	SELF_CGROUP_FILE    = "/proc/self/cgroup"
	GET_DOCKER_UUID_REG = `1:name=systemd:.*([a-z0-9]{64}).*`
	MATCH_RST_LEN       = 2

	// judge virtual guest os
	DMI_PRODUCT_UUID     = "/sys/class/dmi/id/product_uuid"
	DMI_PRODUCT_NAME     = "/sys/class/dmi/id/product_name"
	KVM_NAME             = "KVM Virtual Machine"
	NOT_DOCKER_CONTAINER = "not docker container"
)

type (
	QcaDaemonFlags struct {
		Hostserver string
	}
)

func InitFlags() *QcaDaemonFlags {
	var flags = QcaDaemonFlags{}
	pflag.StringVarP(&flags.Hostserver, "hostserver", "H", "", "host server addr ip:port")
	pflag.Parse()

	return &flags
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
	match := regexp.MustCompile(GET_DOCKER_UUID_REG).FindStringSubmatch(string(con))
	if len(match) == MATCH_RST_LEN {
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
		reportIn := make([]byte, 0)
		if err = qcatools.RecvData(conn, &reportIn); err != nil {
			log.Printf("Read ra_server forward request data failed, %v\n", err)
			return
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
			log.Printf("Send register info to ra_server failed, %v\n", err)
			return
		}

	}
}
