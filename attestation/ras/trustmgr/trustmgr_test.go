package trustmgr

/*
import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	constPath = "/reports"
	constDB   = "postgres"
	constDNS  = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"
)

func TestCreateAndClose(t *testing.T) {
	path, _ := os.Getwd()
	mgr, _ := NewTrustMgr(path+constPath, constDB, constDNS)
	defer mgr.Close()
}

func TestRegisterClientByAK(t *testing.T) {
	clients := []struct {
		AK   string
		Info string
	}{
		{"1", `{"ip": "10.0.0.1", "name": "wucaijun1", "num": 123}`},
		{"2", `{"ip": "10.0.0.2", "name": "wucaijun2", "num": 123}`},
		{"3", `{"ip": "10.0.0.3", "name": "wucaijun3", "num": 123}`},
		{"4", `{"ip": "10.0.0.4", "name": "wucaijun4", "num": 123}`},
		{"5", `{"ip": "10.0.0.5", "name": "wucaijun5", "num": 123}`},
		{"6", `{"ip": "10.0.0.6", "name": "wucaijun6", "num": 123}`},
		{"7", `{"ip": "10.0.0.7", "name": "wucaijun7", "num": 123}`},
	}
	path, _ := os.Getwd()
	mgr, _ := NewTrustMgr(path+constPath, constDB, constDNS)
	defer mgr.Close()
	for _, c := range clients {
		mgr.RegisterClientByAK(c.AK+time.Now().Format("06-01-02-15-04-05.999"), c.Info)
	}
}

func TestFindClient(t *testing.T) {
	path, _ := os.Getwd()
	mgr, _ := NewTrustMgr(path+constPath, constDB, constDNS)
	defer mgr.Close()
	ak := "AK" + time.Now().Format("06-01-02-15-04-05") + "KA"
	info := fmt.Sprintf(`{"ip": "8.8.8.%d", "name": "google DNS", "last": %d}`, time.Now().Second(), time.Now().Second())
	c, err := mgr.RegisterClientByAK(ak, info)
	if err != nil {
		t.Logf("register fail %v", err)
	}
	c1, err := mgr.FindClientByAK(c.AK)
	if err == nil {
		t.Logf("find client by ak=%s, c=%v\n", c1.AK, c1)
	} else {
		t.Errorf("find by ak error: %v", err)
	}
	c2, err := mgr.FindClientByID(c.ID)
	if err == nil {
		t.Logf("find client by id=%d, c=%v\n", c2.ID, c2)
	} else {
		t.Errorf("find by id error: %v", err)
	}
	info2 := `{"name": "google DNS"}`
	c3, err := mgr.FindClientsByInfo(info2)
	if err == nil {
		t.Logf("find client by info=%s\n", info2)
		for i, v := range c3 {
			t.Logf("  %d, %v\n", i, v)
		}
	} else {
		t.Errorf("find by info error: %v", err)
	}
}

func TestSaveReport(t *testing.T) {
	path, _ := os.Getwd()
	mgr, _ := NewTrustMgr(path+constPath, constDB, constDNS)
	defer mgr.Close()
	ak := "AK" + time.Now().Format("06-01-02-15-04-05") + "KA"
	info := fmt.Sprintf(`{"ip": "8.8.8.%d", "name": "google DNS", "last": %d}`, time.Now().Second(), time.Now().Second())
	c, err := mgr.RegisterClientByAK(ak, info)
	if err != nil {
		t.Logf("register fail %v", err)
	}
	_ = c
	//mgr.SaveReport(c.ID, []byte("haha"))
}

func TestJson(t *testing.T) {
	a := IndexFile{
		[]BaseInfo{
			{"basefile", "bpcrfile", "biosfile", true},
		},
		[]ReportInfo{
			{time.Now().Format("2006-01-02 15:04:05"), "report1", "rpcr1", "quote", true},
			{"2021-01-02 15:04:05", "report2", "rpcr2", "quote", false},
			{"2021-01-03 15:04:05", "report3", "rpcr3", "quote", true},
		},
	}
	str, _ := json.Marshal(a)
	fmt.Printf("%s\n", str)

	b := make(map[string]string)
	b["os"] = "ubuntu"
	b["ip"] = "10.1.1.1"
	b["version"] = "1.0"
	str, _ = json.Marshal(b)
	fmt.Printf("%s\n", str)

	var aa IndexFile
	m := []byte(`{"Base":[{"BaseFile":"base","BiosFile":"bios==","Enabled":true}],"Report":[{"ReceiveTime":"2021-01-13","ReportFile":"report","RpcrFile":"rpcr","QuoteFile":"quote","Verified":true},{"ReceiveTime":"2021-01-14","ReportFile":"report2","RpcrFile":"rpcr2","QuoteFile":"quote2"}]}`)
	json.Unmarshal(m, &aa)
	fmt.Printf("aa:%v\n", aa)
}
*/
