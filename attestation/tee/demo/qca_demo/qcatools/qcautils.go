package qcatools

/*
#cgo CFLAGS: -I../../../../rac/ka/teesimulator -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lteec_adaptor -lteec -lqca -ldl

#include "teeqca.h"
#include "tee.h"
#include "teeqca.h"
#include <stdlib.h>
#include <pthread.h>

#define MAX_INDEX 0x100000

static const TEEC_UUID g_qtaUuid = {
	0xe08f7eca, 0xe875, 0x440e, {0x9a, 0xb0, 0x5f, 0x38, 0x11, 0x36, 0xc6, 0x00}
};

struct CtxSessList {
	uint32_t index;
	TEEC_Context ctx;
	TEEC_Session sess;
	struct CtxSessList *next;
	struct CtxSessList *prev;
};

static uint32_t g_curIndex = 0;
static struct CtxSessList g_listHead;
static bool g_isInitList = false;
static pthread_mutex_t g_listLock = PTHREAD_MUTEX_INITIALIZER;

static inline void initHead(struct CtxSessList *head)
{
	head->next = head;
	head->prev = head;
}

static inline void insertTail(struct CtxSessList *head, struct CtxSessList *node)
{
	struct CtxSessList *tail = head->prev;
	tail->next = node;
	node->prev = tail;
	node->next = head;
	head->prev = node;
}

static inline struct CtxSessList *findNode(struct CtxSessList *head, uint32_t index)
{
	struct CtxSessList *cur = head->next;
	for (; cur != head; cur = cur->next) {
		if (cur->index == index) {
			return cur;
		}
	}
	return NULL;
}

static inline void deleteNode(struct CtxSessList *node)
{
	if (node == &g_listHead) {
		return;
	}
	struct CtxSessList *pre = node->prev;
	pre->next = node->next;
	node->next->prev = pre;
}


static struct CtxSessList *mallocAddList(void)
{
	struct CtxSessList *node = (struct CtxSessList *)calloc(1, sizeof(struct CtxSessList));
	if (node == NULL) {
		printf("[c] calloc new node failed\n");
		return NULL;
	}

	if (pthread_mutex_lock(&g_listLock) != 0) {
		printf("[c] thread lock failed\n");
		free(node);
		return NULL;
	}

	g_curIndex++;
	g_curIndex &= (MAX_INDEX - 1);
	node->index = g_curIndex;
	if (!g_isInitList) {
		initHead(&g_listHead);
		g_isInitList = true;
	}
	insertTail(&g_listHead, node);

	(void)pthread_mutex_unlock(&g_listLock);
	return node;
}

static struct CtxSessList *deleteNodeList(uint32_t index)
{
	if (!g_isInitList) {
		printf("[c] should use this after init\n");
		return NULL;
	}
	if (pthread_mutex_lock(&g_listLock) != 0) {
		printf("[c] thread lock failed\n");
		return NULL;
	}

	struct CtxSessList *node = findNode(&g_listHead, index);
	if (node == NULL) {
		printf("[c] not found the target node\n");
		(void)pthread_mutex_unlock(&g_listLock);
		return NULL;
	}

	deleteNode(node);

	(void)pthread_mutex_unlock(&g_listLock);
	return node;
}

void CloseCtxAndSess(uint32_t index, char *id)
{
	struct CtxSessList *node = deleteNodeList(index);
	if (node == NULL) {
		return;
	}

	(void)UnRegisterContainerWithSess(id, &node->sess);
	TEEC_CloseSession(&node->sess);
    TEEC_FinalizeContext(&node->ctx);
	free(node);
}

int RegisterVirtualGuest(struct ra_buffer_data *container_info)
{
	struct CtxSessList *node = mallocAddList();
	if (node == NULL) {
		printf("[c] malloc context and session failed\n");
		return -1;
	}
	int ret = TEEC_InitializeContext(NULL, &node->ctx);
	if (ret) {
		printf("[c] init context failed, ret = %x\n", ret);
		ret = -1;
		goto end;
	}

	TEEC_Operation opt = {0};
	opt.started = 1;
	opt.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	ret = TEEC_OpenSession(&node->ctx, &node->sess, &g_qtaUuid, TEEC_LOGIN_IDENTIFY, NULL, &opt, NULL);
	if (ret) {
		printf("[c] open session failed, ret = %x\n", ret);
		ret = -1;
		TEEC_FinalizeContext(&node->ctx);
		goto end;
	}

	uint32_t origin = 0;
	ret = RegisterContainer(container_info, &node->ctx, &node->sess, &origin);
	if (ret) {
		printf("[c] register virtual guest failed, ret = %x, origin = %x\n", ret, origin);
		ret = -1;
		TEEC_CloseSession(&node->sess);
    	TEEC_FinalizeContext(&node->ctx);
		goto end;
	}
	return node->index;

end:
	(void)deleteNodeList(node->index);
	free(node);
	return ret;
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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
	"encoding/binary"

	"github.com/docker/docker/client"
)

const (
	MAX_CONN_CNT     = 512
	MAX_REGBUF_SIZE  = 512
	DOCKER_ID_LEN    = 64
	KVM_UUID_LEN     = 36
	MAX_HEALTH_CHECK = 7 * 24 * 60 // 7 day

	RET_SUCCESS       = 0
	RET_CALLCERR      = 1
	RET_SAVECLIENTERR = 2

	GET_QEMU_PID_FMT = "ps aux | grep qemu.*%s | grep -v grep | awk '{print $2}'"

	NSID_MATCH_RET = 2
)

var (
	connMap    sync.Map
	curConnCnt int32
)

type (
	RegVirtGuestInfo struct {
		Id   string `json:"container_id"` // 兼容tee
		Nsid int    `json:"nsid"`
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
	if err := conn.(net.Conn).Close(); err != nil {
		log.Printf("delete conn failed, %v\n", err)
	}
	cid := C.CString(id)
	defer C.free(unsafe.Pointer(cid))
	C.UnRegisterContainer(cid)
}

func CheckConnAlive(check int32, done chan bool) {
	if check <= 0 || check > MAX_HEALTH_CHECK {
		return
	}
	ticker := time.NewTicker(time.Duration(check) * time.Minute)
	for {
		select {
		case <-done:
			connMap.Range(func(id, conn interface{}) bool {
				deleteConnClient(id.(string))
				return true
			})
			return

		case <-ticker.C:
			log.Println("Start connect health check....")
			connMap.Range(func(id, conn interface{}) bool {
				err := connCheck(conn.(net.Conn))
				if err != nil {
					log.Printf("Close inactive connection %v\n", id)
					deleteConnClient(id.(string))
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

	match := regexp.MustCompile(`\[([0-9]+)\]`).FindStringSubmatch(cont)
	if len(match) == NSID_MATCH_RET {
		nsid, err := strconv.Atoi(match[1])
		if err != nil {
			return -1, fmt.Errorf("convert to int failed, %v", err)
		}
		return nsid, nil
	}
	return -1, fmt.Errorf("regexp not match")
}

func getDockerNsidById(id string) (int, error) {
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

/* kvm nsid same as host, so current solution is use qemu pid replace nsid */
func getKvmNsidByUuid(uuid string) (int, error) {
	queryCmd := fmt.Sprintf(GET_QEMU_PID_FMT, uuid)
	cmd := exec.Command("bash", "-c", queryCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("exec query cmd failed, %v", err)
	}
	outstr := string(out)
	outstr = strings.Trim(outstr, " \n")
	if len(outstr) == 0 {
		return -1, fmt.Errorf("query target qemu pid failed, %v", err)
	}

	pid, err := strconv.Atoi(outstr)
	if err != nil {
		return -1, fmt.Errorf("convert to int failed, %v", err)
	}
	return pid, nil
}

func getVirtGuestNsidByInfo(info *VirtualGuestInfo) (int, error) {
	switch info.Type {
	case "docker":
		return getDockerNsidById(info.Id)
	case "kvm":
		return getKvmNsidByUuid(info.Id)
	default:
		return -1, fmt.Errorf("not support type")
	}
}

func SendData(conn net.Conn, data interface{}, errno int) error {

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

	jsonlen := len(injson)
	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(jsonlen))

	n, err := conn.Write(lenbuf)
	if err != nil || n != len(lenbuf) {
		return fmt.Errorf("send data len failed, %v", err)
	}

	n, err = conn.Write(injson)
	if err != nil || n != len(injson) {
		return fmt.Errorf("send data failed, %v", err)
	}

	return nil
}

func RecvData(conn net.Conn, outData interface{}) error {
	
	lenbuf := make([]byte, 4)
	n, err := conn.Read(lenbuf)
	if err != nil {
		return fmt.Errorf("read from connection failed, %v", err)
	}

	readlen := binary.BigEndian.Uint32(lenbuf)
	buf := make([]byte, 0)
	partbuf := make([]byte, readlen)

	for {
		n, err = conn.Read(partbuf)

		if err!= nil || n == 0 {
			return fmt.Errorf("read data failed, %v", err)
		}

		buf = append(buf, partbuf...)
		
		if len(buf) == int(readlen) {
			break
		}
	}

	var data ConnWrapMsg
	err = json.Unmarshal(buf[:readlen], &data)
	if  err != nil {
		return fmt.Errorf("message unmarshal failed, %v", err)
	}
	if data.Ret != 0 {
		var msg []byte
		err = json.Unmarshal([]byte(data.Data), &msg)
		if err != nil {
			return fmt.Errorf("get errmsg failed, %v", err)
		}
		return fmt.Errorf("remote return err, %d, %v", data.Ret, string(msg))
	}

	if err = json.Unmarshal([]byte(data.Data), &outData); err != nil {
		return fmt.Errorf("data unmarshal failed, %v", err)
	}
	return nil
}

func dealQcaDaemonClient(conn net.Conn) {
	closeConn := func() {
		if err := conn.Close(); err != nil {
			log.Printf("close conn fialed, %v\n", err)
		}
	}

	var cliInfo VirtualGuestInfo
	err := RecvData(conn, &cliInfo)
	if err != nil {
		log.Printf("Recv client regist info failed, %v\n", err)
		closeConn()
		return
	}

	/* recive kvm id is 64 id */
	err = addConnClient(cliInfo.Id, conn)
	if err != nil {
		log.Printf("Save conn to map failed, %v\n", err)
		err = SendData(conn, []byte("save conn to map falied"), RET_SAVECLIENTERR)
		if err != nil {
			log.Printf("send fail msg to qca_daemon failed, %v\n", err)
		}
		closeConn()
		return
	}

	err = SendData(conn, []byte("client register success"), RET_SUCCESS)
	if err != nil {
		log.Printf("send success to qca_daemon failed.\n")
		closeConn()
	}

	log.Println("Regist qca_daemon client success")
}

func StartQcaDaemonServer(saddr string, done chan bool) {
	listen, err := net.Listen("tcp", saddr)
	if err != nil {
		log.Fatalf("Listen %v failed, %v", saddr, err)
	}
	log.Printf("Start tcp server on %v\n", saddr)

	for {
		select {
		case <-done:
			return
		default:
			conn, err := listen.Accept()
			if err != nil {
				log.Printf("Accept failed, %v", err)
				continue
			}
			go dealQcaDaemonClient(conn)
		}
	}
}

func checkVirtGuestInfo(info *VirtualGuestInfo) error {
	info.Id, info.Type = strings.ToLower(info.Id), strings.ToLower(info.Type)
	// no container info input is valid
	if info.Id == "" && info.Type == "" {
		return nil
	}

	if info.Id == "" || info.Type == "" {
		return fmt.Errorf("id or type lacked")
	}
	switch info.Type {
	case "docker":
		if len(info.Id) != DOCKER_ID_LEN {
			return fmt.Errorf("invalid id length %d", len(info.Id))
		}
	case "kvm":
		if len(info.Id) != KVM_UUID_LEN {
			return fmt.Errorf("invalid uuid length %d", len(info.Id))
		}
	default:
		return fmt.Errorf("not supported container type")
	}
	return nil
}

func dealVirtualTAReq(info *VirtualGuestInfo, data []byte) ([]byte, error) {

	err := checkVirtGuestInfo(info)
	if err != nil {
		return nil, fmt.Errorf("invalid client info, %v", err)
	}

	conn := findConnClient(info.Id)
	if conn == nil {
		return nil, fmt.Errorf("can't find client")
	}

	nsid, err := getVirtGuestNsidByInfo(info)
	if err != nil {
		return nil, fmt.Errorf("get virtual guest nsid failed, %v", err)
	}

	// register info in qta adapt kvm
	newInfo, err := adaptkvm(info)
	if err != nil {
		return nil, fmt.Errorf("adapt kvm machine failed, %v", err)
	}

	reginfo := &RegVirtGuestInfo{
		Id:   newInfo.Id,
		Nsid: nsid,
	}

	inparamjson, err := json.Marshal(reginfo)
	if err != nil {
		return nil, fmt.Errorf("encode containter register info error, %v", err)
	}

	index, err := callCRegisterContainer(inparamjson)
	if err != nil {
		return nil, err
	}
	cid := C.CString(newInfo.Id)
	/* defer exec order like stack */
	defer C.free(unsafe.Pointer(cid))
	defer C.CloseCtxAndSess(C.__uint32_t(index), cid)

	if err = SendData(conn, data, RET_SUCCESS); err != nil {
		return nil, fmt.Errorf("forward req to qca_daemon failed, %v", err)
	}
	var report []byte
	if err = RecvData(conn, &report); err != nil {
		return nil, fmt.Errorf("get qca_daemon resp failed, %v", err)
	}
	return report, nil
}

func callCRegisterContainer(js_input []byte) (int, error) {
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(js_input))
	up_c_in := C.CBytes(js_input)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	ret := C.RegisterVirtualGuest(&c_in)
	if ret < 0 {
		return -1, fmt.Errorf("call libqca register container failed, ret %v", ret)
	}
	return int(ret), nil
}

func CallCRemoteAttest(js_input []byte, out_len uint32) ([]byte, error) {
	if len(js_input) == 0 || out_len == 0 {
		return nil, errors.New("invalid json input or output len")
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

	teec_result := C.RemoteAttest(&c_in, &c_out)
	if int(teec_result) != 0 {
		return nil, errors.New("invoke remoteAttest failed")
	}

	output := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))

	return output, nil
}
