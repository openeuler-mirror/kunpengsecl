package qcatools

/*
#cgo CFLAGS: -I../../../../rac/ka/teesimulator -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lteec_adaptor -lteec -lqca -ldl

#include "teeqca.h"
#include "tee.h"
#include "teeqca.h"

static const TEEC_UUID g_qta_uuid = {
	0xe08f7eca, 0xe875, 0x440e, {0x9a, 0xb0, 0x5f, 0x38, 0x11, 0x36, 0xc6, 0x00}
};

uint32_t InitCtxAndOpenSess(TEEC_Context *ctx, TEEC_Session *sess)
{
	uint32_t ret = TEEC_InitializeContext(NULL, ctx);
	if (ret) {
		printf("[c] init context failed, ret = %x\n", ret);
		return ret;
	}
	TEEC_Operation opt = {0};
	opt.started = 1;
	opt.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	ret = TEEC_OpenSession(ctx, sess, &g_qta_uuid, TEEC_LOGIN_IDENTIFY, NULL, &opt, NULL);
	if (ret) {
		printf("[c] open session failed, ret = %x\n", ret);
		TEEC_FinalizeContext(ctx);
	}
	return ret;
}

uint32_t MallocCtxAndSess()


void CloseSessAndCtx(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_CloseSession(sess);
    TEEC_FinalizeContext(ctx);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/docker/docker/client"
)

const (
	MAX_CONN_CNT     = 512
	MAX_OUTBUF_SIZE  = 0x3000
	MAX_REGBUF_SIZE  = 512
	DOCKER_ID_LEN    = 64
	MAX_HEALTH_CHECK = 7 * 24 * 60 // 7 day

	RET_SUCCESS  = 0
	RET_CALLCERR = 1
)

var (
	connMap    sync.Map
	curConnCnt int32
	ValidNsid  = regexp.MustCompile(`\[([0-9]+)\]`)
	Done       = make(chan bool)
)

type (
	ContRegistInfo struct {
		Id   string `json:"container_id"`
		Nsid int    `json:"nsid"`
	}

	ClientInfo struct {
		Id   string `json:"id"` // docker and kvm return 64 bytes string
		Type string `json:"type"`
	}

	ConnWrapMsg struct {
		Ret  int    `json:"ret"`
		Data string `json:"data,omitempty"`
	}
)

func findConnClient(id string) net.Conn {
	if id == "" {
		return nil
	}

	conn, ok := connMap.Load(id)
	if ok == false {
		return nil
	}
	return conn.(net.Conn)
}

func addConnClient(id string, conn net.Conn) error {
	if id == "" || conn == nil {
		return fmt.Errorf("invalid input")
	}

	_, ok := connMap.Load(id)
	if ok == false {
		if atomic.LoadInt32(&curConnCnt) >= MAX_CONN_CNT {
			return fmt.Errorf("too much connect for ra_server")
		}
		atomic.AddInt32(&curConnCnt, 1)
	}
	connMap.Store(id, conn)
	return nil
}

func deleteConnClient(id string) {
	if id == "" {
		return
	}

	conn, ok := connMap.Load(id)
	if ok == false {
		return
	}
	atomic.AddInt32(&curConnCnt, -1)
	connMap.Delete(id)
	conn.(net.Conn).Close()
}

func CheckConnAlive(check int32) {
	if check <= 0 || check > MAX_HEALTH_CHECK {
		return
	}
	ticker := time.NewTicker(check * time.Minute)
	for {
		select {
		case <-done:
			connMap.Range(func(id, conn interface{}) bool {
				conn.(net.Conn).Close()
				return true
			})
			return

		case <-ticker.C:
			connMap.Range(func(id, conn interface{}) bool {
				err := connCheck(conn.(net.Conn))
				if err != nil {
					atomic.AddInt32(&curConnCnt, -1)
					connMap.Delete(id)
					conn.(net.Conn).Close()
				}
				return true
			})
		}
	}
}

func connCheck(conn net.Conn) error {
	var sysErr error

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return err
	}

	err = rawConn.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, err := syscall.Read(int(fd), buf[:])
		switch {
		case n == 0 && err == nil:
			sysErr = io.EOF
		case n > 0:
			sysErr = fmt.Errorf("unexpected read from socket")
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			sysErr = nil
		default:
			sysErr = err
		}
		return true
	})
	if err != nil {
		return err
	}

	return sysErr
}

func getNsidByPid(pid int) (int, error) {
	if pid <= 0 {
		return -1, fmt.Errorf("get invalid pid")
	}

	cont, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
	if err != nil {
		return -1, fmt.Errorf("readlink failed, %v", err)
	}

	match := ValidNsid.FindStringSubmatch(cont)
	if len(match) == 2 {
		if nsid, err := strconv.Atoi(match[1]); err != nil {
			return -1, fmt.Errorf("convert to int failed, %v", err)
		}
		return nsid, nil
	}
	return -1, fmt.Errorf("regexp not match")
}

func getDockerNsidById(id string) (int, error) {
	if len(id) != DOCKER_ID_LEN {
		return -1, fmt.Errorf("invalid docker container id")
	}

	cli, err := client.NewEnvClient()
	if err != nil {
		return -1, fmt.Errorf("create docker client failed, %v", err)
	}
	defer cli.Close()

	ctx := context.Background()
	id = strings.ToLower(id)
	conInfo, err := cli.ContainerInspect(ctx, id)
	if err != nil {
		return -1, fmt.Errorf("get container info failed, %v", err)
	}

	if conInfo.State.Running == false {
		return -1, fmt.Errorf("container is not running")
	}

	return getNsidByPid(conInfo.State.Pid)
}

func SendData(conn net.Conn, data interface{}, errno int) error {
	err := connCheck(conn)
	if err != nil {
		return fmt.Errorf("conn is not alive, %v", err)
	}

	datajs, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("data marshl failed, %v", err)
	}

	cwmsg := ConnWrapMsg{
		Ret:  errno,
		Data: string(datajs),
	}
	injson, err := json.Marshal(cwmsg)
	if err != nil {
		return fmt.Errorf("message marshl failed, %v", err)
	}

	n, err := conn.Write(injson)
	if err != nil || n != len(injson) {
		return fmt.Errorf("send data failed, %v", err)
	}

	return nil
}

func RecvData(conn net.Conn, outData interface{}) error {
	err := connCheck(conn)
	if err != nil {
		return fmt.Errorf("conn is not alive, %v", err)
	}

	var buf [MAX_OUTBUF_SIZE]byte
	n, err := conn.Read(buf[:])
	if err != nil || n == 0 {
		return fmt.Errorf("read data failed, %v", err)
	}

	var data ConnWrapMsg
	if err = json.Unmarshal(buf[:n], &data); err != nil {
		return fmt.Errorf("message unmarshal failed, %v\n", err)
	}
	if data.Ret != 0 {
		return fmt.Errorf("remote return err, %d\n", data.Ret)
	}

	if err = json.Unmarshal([]byte(data.Data), &outData); err != nil {
		return fmt.Errorf("data unmarshal failed, %v\n", err)
	}
	return nil
}

func dealQcaDaemonClient(conn net.Conn) {
	var cliInfo ClientInfo
	err := RecvData(conn, &cliInfo)
	if err != nil {
		log.Printf("recv client regist info failed, %v\n", err)
		goto close
	}

	err = addConnClient(cliInfo.Id, conn)
	if err != nil {
		log.Printf("save conn to map failed, %v\n", err)
		goto close
	}

	log.Println("client register success\n")
	return

close:
	conn.Close()
}

func StartQcaDaemonServer(saddr string) {
	listen, err := net.Listen("tcp", saddr)
	if err != nil {
		log.Fatalf("listen %v failed, %v", saddr, err)
	}
	for {
		select {
		case <-done:
			return
		default:
			conn, err := listen.Accept()
			if err != nil {
				log.Printf("accept failed, %v", err)
				continue
			}
			go dealQcaDaemonClient(conn)
		}
	}
}

func dealDockerTAReq(id string, data []byte) ([]byte, error) {
	id = strings.ToLower(id)
	if len(id) != DOCKER_ID_LEN {
		return nil, fmt.Errorf("docker ta request, docker id len invalid %v", len(id))
	}
	conn := findConnClient(id)
	if conn == nil {
		return nil, fmt.Errorf("can't find client")
	}

	nsid, err := getDockerNsidById(id)
	if err != nil {
		return nil, fmt.Errorf("get docker nsid failed, %v", err)
	}

	info := &ContRegistInfo{
		Id:   id,
		Nsid: nsid,
	}

	inparamjson, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("encode docker regist json message error, %v", err)
	}

	ctx := C.TEEC_Context{}
	sess := C.TEEC_Session{}
	ret := C.InitCtxAndOpenSess(&ctx, &sess)
	if ret != 0 {
		return nil, fmt.Errorf("Init tee context or open session failed %v", ret)
	}
	defer C.CloseSessAndCtx(&ctx, &sess)

	if err = callCRegisterContainer(inparamjson, &ctx, &sess); err != nil {
		return nil, err
	}

	if err = SendData(conn, data, RET_SUCCESS); err != nil {
		return nil, fmt.Errorf("forward req to qca_daemon failed, %v", err)
	}
	var report []byte
	if err = RecvData(conn, &report); err != nil {
		return nil, fmt.Errorf("get qca_daemon resp failed, %v", err)
	}
	return report, nil
}

func callCRegisterContainer(js_input []byte, ctx *C.TEEC_Context, sess *C.TEEC_Session) error {
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(js_input))
	up_c_in := C.CBytes(js_input)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	c_ori := C.__uint32_t(0)

	ret := C.RegisterContainer(&c_in, ctx, sess, &c_ori)
	if ret != 0 {
		return fmt.Errorf("call libqca register container failed, ret %v, origin %v", ret, c_ori)
	}
	return nil
}

func CallCRemoteAttest(js_input []byte, out_len uint32) ([]byte, error) {
	if js_input == nil || out_len == 0 {
		return nil, errors.New("invalid json input or lens")
	}

	/*** format conversion: Go -> C ***/
	// in parameter conversion
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(js_input))
	up_c_in := C.CBytes(js_input)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	c_out := C.struct_ra_buffer_data{}
	c_out.size = C.__uint32_t(out_len)
	up_c_out := C.malloc(C.ulong(c_out.size))
	c_out.buf = (*C.uint8_t)(up_c_out)
	defer C.free(up_c_out)

	teec_result := C.RemoteAttest(&c_in, &c_out)
	if int(teec_result) != 0 {
		return nil, errors.New("Invoke remoteAttest failed")
	}

	output := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))

	return output, nil
}
