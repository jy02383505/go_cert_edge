package main

import (
	"bytes"
	//"coder"
	ut "MESGo/utils"
	"bufio"
	"compress/zlib"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	ra "math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

//var centerip = ut.Centerip
//var centerport = ut.Centerport

var log = ut.Logger
var serverPort = ut.ServerPort
var CENTERIP = ut.CENTERIP
var CENTERPORT = ut.CENTERPORT
var FILESAVEPATH = ut.FILESAVEPATH
var CENTERIPLIST = strings.Split(CENTERIP, ",")

type DataFromCenter struct {
	Username  string `json:"username"`
	Cert      string `json:"cert"`
	Cert_name string `json:"cert_name"`
	S_name    string `json:"s_name"`
	S_dir     string `json:"s_dir"`
	P_key     string `json:"p_key"`
	Task_id   string `json:"task_id"`
	Seed      string `json:"seed"`
	Cert_type string `json:"cert_type"`
}

type TransdataFromCenter struct {
	O_path    string `json:"o_path"`
	D_path    string `json:"d_path"`
	Save_name string `json:"save_name"`
	Task_id   string `json:"task_id"`
}

type QuerydataFromCenter struct {
	Query_path        string `json:"query_path"`
	Query_config_path string `json:"query_config_path"`
	Query_cert_name   string `json:"query_cert_name"`
	Query_cert_type   string `json:"query_cert_type"`
	Task_id           string `json:"task_id"`
}

type DataFromCenterPullday struct {
	Add_cert      []DataFromCenter      `json:"add_cert"`
	Transfer_cert []TransdataFromCenter `json:"transfer_cert"`
}
type Message struct {
	Status  int    `json:"status"`
	Task_id string `json:"task_id"`
}
type PullSendData struct {
	Hostname   string   `json:"hostname"`
	Sign       string   `json:"sign"`
	Ignore_crt []string `json:"ignore_crt"`
}

type PullSendDataday struct {
	Hostname string `json:"hostname"`
	Sign     string `json:"sign"`
	Version  string `json:"version"`
}
type Datacompress struct {
	Status int    `json:"status"`
	Desc   string `json:"desc"`
}

type TransferpostData struct {
	Status  int            `json:"status"`
	Info    map[string]int `json:"info"`
	Task_id string         `json:"task_id"`
}

type QuerypostData struct {
	Status  int                    `json:"status"`
	Info    map[string]interface{} `json:"info"`
	Task_id string                 `json:"task_id"`
}

type TransferInfo struct {
	o_path    string
	d_path    string
	form      string
	save_name string
	task_id   string
}

type QuerycertInfo struct {
	Cert_exit       bool   `json:"cert_exits"`
	Cert_type       string `json:"cert_type"`
	Cert_info       string `json:"cert_info"`
	Sha256cert      string `json:"sha256cert"`
	Cert_exitinconf bool   `json:"cert_exitinconf"`
}

type QuerykeyInfo struct {
	Key_exit       bool   `json:"key_exits"`
	Key_info       string `json:"key_info"`
	Sha256key      string `json:"sha256key"`
	Key_exitinconf bool   `json:"key_exitinconf"`
}
type TransfeResult struct {
	status    int
	save_name string
	form      string
}

var pub_key []byte
var privateKey []byte

func TaskRequestPost(w http.ResponseWriter, r *http.Request) { //接收中央下发的证书下发任务
	if r.Method != "POST" {
		//nonPostData, _ := ioutil.ReadAll(DoZlibUnCompress([]byte(r.Body)))
		nonPostData, _ := ioutil.ReadAll(r.Body)
		log.Debugf("nonPostData %s", nonPostData)
		return
	} else {

		//log.Debugf(reflect.TypeOf(r.Body))
		var data []DataFromCenter
		result, _ := ioutil.ReadAll(r.Body)

		r.Body.Close()

		d, decompress_err := DoZlibUnCompress([]byte(result))
		if decompress_err != nil {

			log.Error("decompress occur error %s", decompress_err)
			b := Datacompress{406, "decompress cert task fail"}
			msg, _ := json.Marshal(b)
			_, errWrite := w.Write([]byte(msg))
			if errWrite != nil {
				http.Error(w, "Interal ERROR: ", 500)
				return
			}
			return
		}
		errunmarshal := json.Unmarshal(d, &data)
		if errunmarshal != nil {
			//log.Error("TaskRequestPost errUnmarshal: ", errUnmarshal)
			log.Error("TaskRequestPost error: %s", errunmarshal)
		}

		//log.Debugf("data type is ", reflect.TypeOf(data))
		log.Debugf("data len is %d", len(data))
		var Tasks_id []string
		for i := 0; i < len(data); i++ {

			Tasks_id = append(Tasks_id, data[i].Task_id)

		}
		ack := NewReceiveBody(data, Tasks_id)
		// ack reply center
		w.WriteHeader(200)
		msg, _ := json.Marshal(ack)
		_, errWrite := w.Write([]byte(msg))
		if errWrite != nil {
			http.Error(w, "Interal ERROR: ", 500)
			return
		}

		ch := make(chan string)
		//for i := 0; i < len(data); i++ {
		//	<-ch
		//}
		var Mess []Message
		for j := 0; j < len(data); j++ {

			go SavefileTask(data[j], ch)
		}
		for i := 0; i < len(data); i++ {
			res := <-ch
			log.Debugf("res is %s", string(res))
			status, err := strconv.Atoi(res[0:3])
			if err != nil {
				log.Debugf(err.Error())
			}

			rest := Message{status, res[3:len(res)]}
			Mess = append(Mess, rest)
		}
		PostRealBody(Mess)
	}
}

func TransferRequestPost(w http.ResponseWriter, r *http.Request) { //接收中央下发的证书转移任务
	if r.Method != "POST" {
		nonPostData, _ := ioutil.ReadAll(r.Body)
		log.Debugf("nonPostData %s", nonPostData)
		return
	} else {

		var data []TransdataFromCenter
		result, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		d, decompress_err := DoZlibUnCompress([]byte(result))
		if decompress_err != nil {
			log.Error("decompress occur error %s", decompress_err)
			b := Datacompress{406, "decompress transfer cert task fail"}
			msg, _ := json.Marshal(b)
			_, errWrite := w.Write([]byte(msg))
			if errWrite != nil {
				http.Error(w, "Interal ERROR: ", 500)
				return
			}
			return
		}
		errunmarshal := json.Unmarshal(d, &data)
		if errunmarshal != nil {
			log.Error("TransferRequestPost error: %s", errunmarshal)
		}
		log.Debugf("data len is %d", len(data))
		var Tasks_id []string
		for i := 0; i < len(data); i++ {
			Tasks_id = append(Tasks_id, data[i].Task_id)
		}
		ack := ReceiveBody(data, Tasks_id)
		// ack reply center
		w.WriteHeader(200)
		msg, _ := json.Marshal(ack)
		_, errWrite := w.Write([]byte(msg))
		if errWrite != nil {
			http.Error(w, "Interal ERROR: ", 500)
			return
		}
		ch := make(chan TransferpostData)
		var Mess []TransferpostData
		for j := 0; j < len(data); j++ {

			go TransferTask(data[j], ch)
		}
		for i := 0; i < len(data); i++ {
			res := <-ch
			//log.Debugf("res is %s", string(res))
			Mess = append(Mess, res)

			log.Debugf("Mess is %+v", Mess)
		}
		PostRealData(Mess)
	}
}

func QueryRequestPost(w http.ResponseWriter, r *http.Request) { //接收中央下发的证书查询任务
	if r.Method != "POST" {
		nonQueryPostData, _ := ioutil.ReadAll(r.Body)
		log.Debugf("nonQueryPostData %s", nonQueryPostData)
		return
	} else {

		var data []QuerydataFromCenter
		result, _ := ioutil.ReadAll(r.Body)
		r.Body.Close()
		d, decompress_err := DoZlibUnCompress([]byte(result))
		if decompress_err != nil {
			log.Error("decompress Query occur error %s", decompress_err)
			b := Datacompress{406, "decompress query cert fail"}
			msg, _ := json.Marshal(b)
			_, errWrite := w.Write([]byte(msg))
			if errWrite != nil {
				http.Error(w, "Interal ERROR: ", 500)
				return
			}
			return
		}
		errunmarshal := json.Unmarshal(d, &data)
		if errunmarshal != nil {
			log.Error("QueryRequestPost occur error: %s", errunmarshal)
		}
		log.Debugf("data len is %d", len(data))
		var Tasks_id []string
		for i := 0; i < len(data); i++ {
			Tasks_id = append(Tasks_id, data[i].Task_id)
		}
		ack := NewReceive(data, Tasks_id)
		// ack reply center
		w.WriteHeader(200)
		msg, _ := json.Marshal(ack)
		_, errWrite := w.Write([]byte(msg))
		if errWrite != nil {
			http.Error(w, "Interal ERROR: ", 500)
			return
		}
		ch5 := make(chan QuerypostData)
		var Mess []QuerypostData
		for j := 0; j < len(data); j++ {

			go QueryfileTask(data[j], ch5)
		}
		for i := 0; i < len(data); i++ {
			res := <-ch5
			//log.Debugf("res is %s", string(res))
			Mess = append(Mess, res)

			log.Debugf("Mess is %+v", Mess)
		}
		PostQueryData(Mess)
	}
}

func TaskPost(w http.ResponseWriter, r *http.Request) { //接收边缘发起的初始化证书任务
	if r.Method != "GET" {
		//nonPostData, _ := ioutil.ReadAll(DoZlibUnCompress([]byte(r.Body)))
		nonPostData, _ := ioutil.ReadAll(r.Body)
		log.Debugf("get nonPostData %s", nonPostData)
		return
	} else {
		r.Body.Close()
		b := Datacompress{200, "success receiver init cert task"}
		msg, _ := json.Marshal(b)
		_, Write_err := w.Write([]byte(msg))
		if Write_err != nil {
			http.Error(w, "Interal ERROR: ", 500)
			return
		}
		//log.Debugf("TaskRequestPost type(request_body): %T|| request_body: %s", result, result)
		go PullcertTask()
	}
}

func TaskPostday(w http.ResponseWriter, r *http.Request) { //接收边缘发起的夜里同步任务
	if r.Method != "GET" {
		//nonPostData, _ := ioutil.ReadAll(DoZlibUnCompress([]byte(r.Body)))
		nonPostData, _ := ioutil.ReadAll(r.Body)
		log.Debugf("get nonPostData %s", nonPostData)
		return
	} else {
		//log.Debugf(reflect.TypeOf(r.Body))
		//var data []DataFromCenter
		r.Body.Close()
		b := Datacompress{200, "success receiver pull cert task"}
		msg, _ := json.Marshal(b)
		_, Write_err := w.Write([]byte(msg))
		if Write_err != nil {
			http.Error(w, "Interal ERROR: ", 500)
			return
		}
		//log.Debugf("TaskRequestPost type(request_body): %T|| request_body: %s", result, result)
		go PullcertdayTask()
	}
}

func Httppost(M []Message) {
	//url := "http://127.0.0.1:9090/checkcert"
	//url := "http://127.0.0.1:8001/internal/cert/trans/result"
	url := "http://" + CENTERIP + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/trans/result"
	log.Debugf("URL: ", url)
	//var M []Message
	//M = append(M, b)
	data, dumps_err := json.Marshal(M)
	log.Error("send transfer cert result dumps occur error is %s", dumps_err)
	log.Debugf("send transfer cert result data is", string(data))
	post := data
	log.Debugf("M is %+v\n", M)
	var jsonStr = []byte(post)
	req, err2 := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err2 != nil {
		//panic(err)
		log.Debugf("err is %s\n", err2)
	}
	// req.Header.Set("X-Custom-Header", "myvalue")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err3 := client.Do(req)
	if err3 != nil {
		log.Debugf("err is %s\n", err3)
		//log.Debugf("err is %s\n", err2)panic(err)
	}
	defer resp.Body.Close()
	log.Debugf("response Status:", resp.Status)
	log.Debugf("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Debugf("response Body:", string(body))
}

func HttptocenterPull(Senddata PullSendData) ([]DataFromCenter, error) {

	center_list := getCENTERIPlist(CENTERIPLIST)
	//url := "http://127.0.0.1:8001/internal/cert/dev/pull"
	url := "http://" + center_list[Generate_Randnum(3)] + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/dev/pull"
	log.Debugf("url is %s:", url)
	log.Debugf("Senddata is %+v:", Senddata)
	json_data, json_err := json.Marshal(Senddata)
	if json_err != nil {
		log.Error("json_err is %s:", json_err.Error())
		return nil, json_err
	}
	log.Debugf("json_data is %s: ", string(json_data))
	data := DoZlibCompres(json_data)
	//o_data := DoZlibUnCompres(data)
	//log.Debugf("o_data is %s", string(o_data))
	req, err1 := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err1 != nil {
		log.Error(err1.Error())
		return nil, err1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "deflate")

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(netw, addr, time.Second*3) //设置建立连接超时
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(time.Second * 60)) //设置发送接受数据超时
				return conn, nil
			},
			ResponseHeaderTimeout: time.Second * 2,
		},
	}
	resp, clientdo_err := client.Do(req)
	if clientdo_err != nil {
		log.Error("pull cert send data to center clientdo occur exception  %s:", clientdo_err.Error())
		return nil, clientdo_err
	}
	defer resp.Body.Close()

	log.Debugf("pull cert response Status is %s", resp.Status)
	log.Debugf("pull cert response Header is %s", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	var datacenter []DataFromCenter
	d, decompress_err := DoZlibUnCompress([]byte(body))
	if decompress_err != nil {
		log.Error("pull cert decompress occur excption %s", decompress_err.Error())
		return nil, decompress_err
	}

	//log.Debugf("type is ", reflect.TypeOf(d))
	unmarshal_err := json.Unmarshal(d, &datacenter)
	if unmarshal_err != nil {
		log.Error("unmarshal cert pull data occur err %s", unmarshal_err.Error())
		return nil, unmarshal_err
	}
	return datacenter, nil
}

func HttptocenterPulldaytask(Senddata PullSendDataday) (DataFromCenterPullday, error) {

	center_list := getCENTERIPlist(CENTERIPLIST)
	//url := "http://127.0.0.1:8001/internal/cert/dev/pull"
	url := "http://" + center_list[Generate_Randnum(3)] + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/dev/day/pull"
	log.Debugf("url is %s:", url)
	log.Debugf("Senddata is %+v:", Senddata)
	json_data, json_err := json.Marshal(Senddata)
	if json_err != nil {
		log.Error("json_err is %s:", json_err.Error())
		return DataFromCenterPullday{}, json_err
	}
	log.Debugf("json_data is %s: ", string(json_data))
	data := DoZlibCompres(json_data)
	//o_data := DoZlibUnCompres(data)
	req, err1 := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err1 != nil {
		log.Error(err1.Error())
		return DataFromCenterPullday{}, err1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "deflate")

	//client := &http.Client{}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(netw, addr, time.Second*3) //设置建立连接超时
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(time.Second * 60)) //设置发送接受数据超时
				return conn, nil
			},
			ResponseHeaderTimeout: time.Second * 2,
		},
	}
	resp, clientdo_err := client.Do(req)
	if clientdo_err != nil {
		log.Error("pull day cert send data to center clientdo occur err %s:", clientdo_err.Error())
		return DataFromCenterPullday{}, clientdo_err
	}
	defer resp.Body.Close()

	log.Debugf("pull cert day response Status is %s", resp.Status)
	log.Debugf("pull cert day response Header is %s", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	var datacenterpullday DataFromCenterPullday
	datafromcenter, decompress_err := DoZlibUnCompress([]byte(body))
	if decompress_err != nil {
		log.Error("decompress err %s", decompress_err.Error())
		return DataFromCenterPullday{}, decompress_err
	}

	//log.Debugf("type is ", reflect.TypeOf(d))
	unmarshal_err := json.Unmarshal(datafromcenter, &datacenterpullday)
	if unmarshal_err != nil {
		log.Error("unmarshal day cert task occur err %s", unmarshal_err.Error())
		return DataFromCenterPullday{}, unmarshal_err
	}
	log.Debugf("datacenterpullday is %s", datacenterpullday)
	return datacenterpullday, nil
}
func PostRealBody(M []Message) { //异步汇报中央

	b, err := json.Marshal(M)
	if err != nil {
		log.Error("jsondumps data is occur error is %s", err)
	}
	body := bytes.NewBuffer([]byte(b))
	//Report_address := "http://127.0.0.1:8001/internal/cert/trans/result"
	//Report_address := "http://" + CENTERIP + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/trans/result"
	for j := 0; j < 1; j++ {
		var i int
		center_list := getCENTERIPlist(CENTERIPLIST)
		for i = 0; i < len(center_list); i++ {
			time.Sleep(time.Second * time.Duration(Generate_Randnum(5)))
			Report_address := "http://" + center_list[i] + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/trans/result"
			//可以通过client中transport的Dial函数,在自定义Dial函数里面设置建立连接超时时长和发送接受数据超时
			client := &http.Client{
				Transport: &http.Transport{
					Dial: func(netw, addr string) (net.Conn, error) {
						conn, err := net.DialTimeout(netw, addr, time.Second*3) //设置建立连接超时
						if err != nil {
							return nil, err
						}
						conn.SetDeadline(time.Now().Add(time.Second * 5)) //设置发送接受数据超时
						return conn, nil
					},
					ResponseHeaderTimeout: time.Second * 2,
				},
			}

			request, errNewRequest := http.NewRequest("POST", Report_address, body) //提交请求;
			if errNewRequest != nil {
				//log.Debugf("PostRealBody retried No.%d times|| errNewRequest: %s|| url_id: %s|| url: %s", i, errNewRequest, data.Url_id, data.Url)
				log.Debugf("PostRealBody retried report %s occur errNewRequest: %s", Report_address, errNewRequest.Error())
				time.Sleep(time.Second * time.Duration(Generate_Randnum(10)))
				continue
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Connection", "close")
			response, errDo := client.Do(request)
			if errDo != nil {
				log.Debugf("PostRealBody retried report %s occur  errDo: %s", Report_address, errDo.Error())
				time.Sleep(time.Second * time.Duration(Generate_Randnum(10)))
				continue
			}
			r_status := response.StatusCode //获取返回状态码，正常是200
			if r_status != 200 {
				log.Debugf("PostRealBody retried  report %s r_status: %d", Report_address, r_status)
				time.Sleep(time.Second * time.Duration(Generate_Randnum(10)))
				continue
			}
			defer response.Body.Close()
			r_body, errReadAll := ioutil.ReadAll(response.Body)
			if errReadAll != nil {
				log.Error("PostRealBody retried retried  report %s occur errReadAll: %s", Report_address, errReadAll)
				return
			}
			log.Debugf("PostRealBody report to %s r_status: %d, r_body: %s", Report_address, r_status, r_body)
			break
		}
		if i >= len(CENTERIPLIST) {
			log.Debugf("PostRealBody retried No.%d times|| body: %s", j, body)
			time.Sleep(time.Second * time.Duration(Generate_Randnum(10)))
			continue
		} else {
			break
		}
	}
}

//"http://" + CENTERIP + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/transfer_cert/result"
func PostRealData(M []TransferpostData) { //转移任务结果异步汇报中央

	b, err := json.Marshal(M)
	if err != nil {
		log.Error("jsondumps data is occur error is %s", err.Error())
	}
	body := bytes.NewBuffer([]byte(b))
	for j := 0; j < 1; j++ {
		var i int
		center_list := getCENTERIPlist(CENTERIPLIST)
		for i = 0; i < len(center_list); i++ {
			Report_address := "http://" + center_list[i] + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/transfer_cert/result"
			//可以通过client中transport的Dial函数,在自定义Dial函数里面设置建立连接超时时长和发送接受数据超时
			client := &http.Client{
				Transport: &http.Transport{
					Dial: func(netw, addr string) (net.Conn, error) {
						conn, err := net.DialTimeout(netw, addr, time.Second*3) //设置建立连接超时
						if err != nil {
							return nil, err
						}
						conn.SetDeadline(time.Now().Add(time.Second * 5)) //设置发送接受数据超时
						return conn, nil
					},
					ResponseHeaderTimeout: time.Second * 2,
				},
			}

			request, errNewRequest := http.NewRequest("POST", Report_address, body) //提交请求;
			if errNewRequest != nil {
				//log.Debugf("PostRealBody retried No.%d times|| errNewRequest: %s|| url_id: %s|| url: %s", i, errNewRequest, data.Url_id, data.Url)
				log.Debugf("PostRealData retried report %s occur errNewRequest: %s", Report_address, errNewRequest.Error())
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Connection", "close")
			response, errDo := client.Do(request)
			if errDo != nil {
				log.Debugf("PostRealData retried report %s occur  errDo: %s", Report_address, errDo.Error())
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			r_status := response.StatusCode //获取返回状态码，正常是200
			if r_status != 200 {
				log.Debugf("PostRealData retried  report %s r_status: %d", Report_address, r_status)
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			defer response.Body.Close()
			r_body, errReadAll := ioutil.ReadAll(response.Body)
			if errReadAll != nil {
				log.Error("PostRealData retried retried  report %s occur errReadAll: %s", Report_address, errReadAll)
				return
			}
			log.Debugf("PostRealData report to %s r_status: %d, r_body: %s", Report_address, r_status, r_body)
			break
		}
		if i >= len(CENTERIPLIST) {
			log.Debugf("PostRealData retried No.%d times|| body: %s", j, body)
			time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
			continue
		} else {
			break
		}
	}

}

func PostQueryData(M []QuerypostData) { //任务结果异步汇报中央

	b, err := json.Marshal(M)
	if err != nil {
		log.Error("jsondumps data is occur error is %s", err)
	}
	body := bytes.NewBuffer([]byte(b))
	for j := 0; j < 1; j++ {
		var i int
		center_list := getCENTERIPlist(CENTERIPLIST)
		for i = 0; i < len(center_list); i++ {
			Report_address := "http://" + center_list[i] + ":" + strconv.Itoa(CENTERPORT) + "/internal/cert/query/result"
			//可以通过client中transport的Dial函数,在自定义Dial函数里面设置建立连接超时时长和发送接受数据超时
			client := &http.Client{
				Transport: &http.Transport{
					Dial: func(netw, addr string) (net.Conn, error) {
						conn, err := net.DialTimeout(netw, addr, time.Second*3) //设置建立连接超时
						if err != nil {
							return nil, err
						}
						conn.SetDeadline(time.Now().Add(time.Second * 5)) //设置发送接受数据超时
						return conn, nil
					},
					ResponseHeaderTimeout: time.Second * 2,
				},
			}

			request, errNewRequest := http.NewRequest("POST", Report_address, body) //提交请求;
			if errNewRequest != nil {
				//log.Debugf("PostRealBody retried No.%d times|| errNewRequest: %s|| url_id: %s|| url: %s", i, errNewRequest, data.Url_id, data.Url)
				log.Debugf("PostQueryBody retried report %s occur errNewRequest: %s", Report_address, errNewRequest.Error())
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Connection", "close")
			response, errDo := client.Do(request)
			if errDo != nil {
				log.Debugf("PostQueryBody retried report %s occur  errDo: %s", Report_address, errDo.Error())
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			r_status := response.StatusCode //获取返回状态码，正常是200
			if r_status != 200 {
				log.Debugf("PostQueryBody retried  report %s r_status: %d", Report_address, r_status)
				time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
				continue
			}
			defer response.Body.Close()
			r_body, errReadAll := ioutil.ReadAll(response.Body)
			if errReadAll != nil {
				log.Error("PostQueryBody retried retried  report %s occur errReadAll: %s", Report_address, errReadAll)
				return
			}
			log.Debugf("PostQueryBody report to %s r_status: %d, r_body: %s", Report_address, r_status, r_body)
			break
		}
		if i >= len(CENTERIPLIST) {
			log.Debugf("PostQueryBody retried No.%d times|| body: %s", j, body)
			time.Sleep(time.Duration(Generate_Randnum(10)) * time.Second)
			continue
		} else {
			break
		}
	}

}
func NewReceiveBody(data []DataFromCenter, tasks_id []string) map[string]interface{} {

	var ack = make(map[string]interface{})
	//var result []ReceiveBody

	ack["task_id"] = tasks_id
	ack["status"] = 200
	return ack
}

func ReceiveBody(data []TransdataFromCenter, tasks_id []string) map[string]interface{} {

	var ack = make(map[string]interface{})
	//var result []ReceiveBody
	//ack1["info"]=
	ack["task_id"] = tasks_id
	ack["status"] = 200
	return ack
}

func NewReceive(data []QuerydataFromCenter, tasks_id []string) map[string]interface{} {

	var ack = make(map[string]interface{})
	//var result []ReceiveBody

	ack["task_id"] = tasks_id
	ack["status"] = 200
	return ack
}
func PullcertTask() { //处理初始化证书任务

	var res []string
	//dir, openfile_error := os.OpenFile("/home/lhh/cert", os.O_RDONLY, os.ModeDir)
	dir, openfile_error := os.OpenFile(FILESAVEPATH, os.O_RDONLY, os.ModeDir)

	if openfile_error != nil {
		log.Debugf("open file occur error %s", openfile_error.Error())
		defer dir.Close()
		//log.Debugf(error.Error())
		return
	}
	names, _ := dir.Readdir(-1)
	var allfile []string
	for _, name := range names {
		filenameWithSuffix := path.Base(name.Name())
		fileSuffix := path.Ext(filenameWithSuffix)
		filenameOnly := strings.TrimSuffix(filenameWithSuffix, fileSuffix)
		allfile = append(allfile, filenameOnly)
	}
	sort.Strings(allfile)
	log.Debugf("all file  is %s", RemoveDuplicatesAndEmpty(allfile))
	res = RemoveDuplicatesAndEmpty(allfile)

	cache_seed := "chinacache"
	hostname := getip()
	deal_hostname := deal(hostname, cache_seed)
	b64_deal_host := string(b64Encode([]byte(deal_hostname)))
	Senddata := PullSendData{hostname, b64_deal_host, res}
	log.Debugf("Senddata is %+v\n", Senddata)
	//PostRealBody(M []PullSendData)
	var Arrayreceiverdata []DataFromCenter
	var err_receive_cert error
	Arrayreceiverdata, err_receive_cert = HttptocenterPull(Senddata)
	if err_receive_cert != nil {
		log.Debugf(" the frist time receiver cert pull data occur err %s", err_receive_cert.Error())
		time.Sleep(time.Second * time.Duration(50))
		Arrayreceiverdata, err_receive_cert = HttptocenterPull(Senddata)
		if err_receive_cert != nil {
			log.Debugf(" the second time receiver cert pull data occur err %s", err_receive_cert.Error())
			return
		}
	}
	log.Debugf("Arrayreceiverdata is %s:", Arrayreceiverdata)
	ch := make(chan string)
	var Mess []Message
	for k := 0; k < len(Arrayreceiverdata); k++ {

		go SavefileTask(Arrayreceiverdata[k], ch)
	}
	var sum int
	for i := 0; i < len(Arrayreceiverdata); i++ {
		a := <-ch
		status, err := strconv.Atoi(a[0:3])
		if err != nil {
			log.Debugf(err.Error())
		}
		b := Message{status, a[3:len(a)]}
		Mess = append(Mess, b)
		//log.Info("pull result is %+v", Mess)
		if status == 200 {
			sum += 1
		}

	}
	log.Debugf("pull result is %+v", Mess)
	log.Debugf("pull cert sum is %d", sum)

	if sum == len(Mess) {
		log.Debugf("update version")
		nowdata := time.Now().Format("20060102")
		writefile_err := writefile(nowdata, "version")
		if writefile_err != nil {
			log.Error("write version occur error %s", writefile_err.Error())
		}
	}
	//nowdata := time.Now().Format("20060102")
	//writefile_err := writefile(nowdata, "version")
	//if writefile_err != nil {
	//	log.Error("writefile occur error %s", writefile_err.Error())
	//}
	//return res
}

func PullcertdayTask() { //处理夜里同步当天任务

	v, err_readversion := ioutil.ReadFile("version")
	if err_readversion != nil {
		log.Debugf("read version occur error %s", err_readversion.Error())
	}
	ver := string(v)
	cache_seed := "chinacache"
	hostname := getip()
	deal_hostname := deal(hostname, cache_seed)
	b64_deal_host := string(b64Encode([]byte(deal_hostname)))
	Senddata := PullSendDataday{hostname, b64_deal_host, ver}
	log.Debugf("pull day cert Senddata is %+v\n", Senddata)
	var receiverdata DataFromCenterPullday
	var err_receive_day_cert error
	receiverdata, err_receive_day_cert = HttptocenterPulldaytask(Senddata)
	if err_receive_day_cert != nil {
		log.Debugf(" frist receiver cert day  pull data occur err %s", err_receive_day_cert.Error())
		time.Sleep(time.Second * time.Duration(50))
		receiverdata, err_receive_day_cert = HttptocenterPulldaytask(Senddata)
		if err_receive_day_cert != nil {
			log.Debugf(" second receiver day cert pull data occur err %s", err_receive_day_cert.Error())
			return
		}
	}
	log.Debugf("pull day cert receiverdata is %s:", receiverdata)
	ch3 := make(chan string)
	ch4 := make(chan TransferpostData)
	var Mess []Message
	var Messa []TransferpostData
	for k := 0; k < len(receiverdata.Add_cert); k++ {

		go SavefileTask((receiverdata.Add_cert)[k], ch3)
	}
	for j := 0; j < len(receiverdata.Transfer_cert); j++ {

		go TransferTask((receiverdata.Transfer_cert)[j], ch4)
	}
	var sum int
	for m := 0; m < len(receiverdata.Add_cert); m++ {
		a := <-ch3
		//log.Debugf("a is %s", string(a))
		status, err := strconv.Atoi(a[0:3])
		if err != nil {
			log.Debugf(err.Error())
		}
		b := Message{status, a[3:len(a)]}
		Mess = append(Mess, b)
		//log.Info("pull result is %+v", Mess)
		sum += 1
	}
	for n := 0; n < len(receiverdata.Transfer_cert); n++ {
		d := <-ch4
		//log.Debugf("res is %s", string(res))
		Messa = append(Messa, d)

		//log.Debugf("Messa is %+v", Messa)
	}
	//log.Debugf("cert transfer result is %+v", Messa)
	log.Debugf("cert pull result is %+v", Mess)
	log.Debugf("cert transfer result is %+v", Messa)
	log.Debugf("pull cert sum is %d", sum)
	num_add_success := 0
	for _, res_addcert := range Mess {

		if res_addcert.Status == 200 {
			num_add_success += 1
		}
	}
	num_transfer_success := 0
	for _, res_transfercert := range Messa {

		if res_transfercert.Info[strings.Replace(res_transfercert.Task_id, ".", "%", -1)] == 200 {
			num_transfer_success += 1
		}

	}
	log.Debugf("add cert success is %d", num_add_success)
	log.Debugf("transfer cert success num is %d", num_transfer_success)

	if num_add_success == len(Mess) && num_transfer_success == len(Messa) {
		log.Debugf("begin update version")
		nowdata := time.Now().Format("20060102")
		writefile_err := writefile(nowdata, "version")
		if writefile_err != nil {
			log.Error("write version occur error %s", writefile_err.Error())
		}
	}
	//return res
}

func Generate_Randnum(num int) int { //获取随机数
	ra.Seed(time.Now().Unix() + int64(os.Getpid()))
	rnd := ra.Intn(num)
	if rnd == 0 {
		return Generate_Randnum(num)
	}
	return rnd
}

func getCENTERIPlist(IP_list []string) []string {

	var nums []int
	nums = generateRandomNumber(1, 5, 4)
	//IP_list := [4]string{"223.202.203.89", "223.202.203.84", "223.202.203.79", "223.202.203.74"}
	list := make([]string, 4)
	for j := 0; j < len(nums); j++ {
		list[j] = IP_list[nums[j]-1]
	}
	return list

}

//获取随机数组
func generateRandomNumber(start int, end int, count int) []int {

	if end < start || (end-start) < count {
		return nil
	}

	nums := make([]int, 0)
	r := ra.New(ra.NewSource(time.Now().UnixNano()))
	for len(nums) < count {
		num := r.Intn((end - start)) + start

		//查重
		exist := false
		for _, v := range nums {
			if v == num {
				exist = true
				break
			}
		}

		if !exist {
			nums = append(nums, num)
		}
	}

	return nums
}

//获取当前设备ip
func getip() string {
	addrs, getip_err := net.InterfaceAddrs()
	if getip_err != nil {
		log.Error("getip error is %s", getip_err)
		os.Exit(1)
	}
	//log.Debugf(addrs)
	var res string
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				res = ipnet.IP.String()
			}
		}
	}
	return res
}

//进行zlib压缩
func DoZlibCompress(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	compressor, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		//catlog.Debug("压缩失败")
		return nil, err
	}
	compressor.Write(input)
	compressor.Close()
	return buf.Bytes(), err
}

//进行zlib解压缩
func DoZlibUnCompress(compressSrc []byte) (res []byte, err error) {
	res = []byte("")
	b := bytes.NewReader(compressSrc)
	var out bytes.Buffer
	r, err := zlib.NewReader(b)
	if err != nil {
		return res, err
	}

	io.Copy(&out, r)
	res = out.Bytes()
	return res, err
}

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(pub_key) //将密钥解析成公钥实例
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData) //RSA算法加密
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey) //将密钥解析成私钥实例
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext) //RSA算法解密
}

//分段加密
func encrypt_trunk(cert string, pub_key string) (string, error) {

	res := ""
	var a int
	//res:=""
	//var buffer bytes.Buffer
	d := cert
	d_len := len(d)
	var err error
	//log.Debugf(a)
	if d_len%245 == 0 {
		a = d_len / 245
	} else {
		a = d_len/245 + 1
	}
	for i := 0; i < a; i++ {
		if 245*(i+1) < d_len {
			b, err := RsaEncrypt([]byte(string(d[245*i : 245*(i+1)])))
			//data, err:=RsaEncrypt([]byte(d))
			if err != nil {
				//panic(err)
				return res, err
			}

			res += string(b)
			//buffer.WriteString(string(RsaEncrypt([]byte(d[245*i:245*(i+1)]))))
		} else {
			//res+=d[245*i:d_len]
			b, err := RsaEncrypt([]byte(d[245*i : d_len]))
			if err != nil {
				//panic(err)
				return res, err
			}
			res += string(b)
			//buffer.WriteString(string(RsaEncrypt([]byte(d[245*i:d_len]))))
		}

	}
	//log.Debugf("RSA加密", res)
	res = base64.StdEncoding.EncodeToString([]byte(res))
	//log.Debugf("RSA", debyte)
	return res, err
}

//res_len := len(res)

//分段解密
func decrypt_trunk(clipher_wen string, pri_key string) (string, error) {

	r := ""
	var err error
	rest, err3 := b64decode(clipher_wen)
	if err3 != nil {
		return r, err3
	}
	//rest := clipher_wen
	rest_len := len(rest)
	//var r string = ""
	var b int
	if rest_len%256 == 0 {
		b = rest_len / 256
	} else {
		b = rest_len/256 + 1
	}
	for i := 0; i < b; i++ {
		if 256*(i+1) < rest_len {
			b, err := RsaDecrypt([]byte(string(rest[256*i : 256*(i+1)])))
			//data, err:=RsaEncrypt([]byte(d))
			if err != nil {
				//panic(err)
				log.Debugf("decrypt err is %s", err.Error())
				return r, err
			}

			r += string(b)
			//buffer.WriteString(string(RsaEncrypt([]byte(d[245*i:245*(i+1)]))))
		} else {
			//res+=d[245*i:d_len]
			b, err := RsaDecrypt([]byte(string(rest[256*i : rest_len])))
			if err != nil {
				//panic(err)
				log.Debugf("decrypt err is %s", err.Error())
				return r, err
			}
			r += string(b)
			//buffer.WriteString(string(RsaEncrypt([]byte(d[245*i:d_len]))))
		}
	}
	//log.Debugf("RSA解密", r)
	return r, err

}

//异或
func deal(data string, seed string) string {
	data_len := len(data)
	seed_len := len(seed)
	r1 := []byte(data)
	r2 := []byte(seed)
	//str := ""
	var str string
	num := 0
	//r2 := []rune(str2)
	for i := 0; i < data_len; i++ {
		if num >= seed_len {
			num = num % seed_len
		}
		f := int(r1[i]) ^ int(r2[num])
		//str += strconv.Itoa(f)
		str += string(f)
		num += 1
	}
	return str
}

//签名
func Sign(fp string, pri_key string) string {
	block2, _ := pem.Decode([]byte(pri_key)) //PiravteKeyData为私钥文件的字节数组
	if block2 == nil {
		log.Debugf("block空")
	}
	//priv即私钥对象,block2.Bytes是私钥的字节流
	priv, err := x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		log.Debugf("无法还原私钥")
		//return nil
	}
	h2 := sha256.New()
	h2.Write([]byte(fp))
	hashed := h2.Sum(nil)
	signature2, err := rsa.SignPKCS1v15(rand.Reader, priv,
		crypto.SHA256, hashed) //签名
	//log.Debugf(string(signature2))
	return string(signature2)

}

//验签
func verify_sign(_signature_fp string, pub_key string, fp string) (bool, error) {

	var err error
	h2 := sha256.New()
	h2.Write([]byte(fp))
	hashed := h2.Sum(nil)
	res := true

	block, _ := pem.Decode([]byte(pub_key))
	if block == nil {
		log.Debugf("block nil")
		res = false
		return res, errors.New("public key error")
		// return
	}
	pubInterface, Parse_err := x509.ParsePKIXPublicKey(block.Bytes)
	if Parse_err != nil {
		log.Debugf("还原公钥错误")
		res = false
		return res, Parse_err
		//return
	}
	pub := pubInterface.(*rsa.PublicKey) //pub:公钥对象
	verify_err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, []byte(_signature_fp))
	if verify_err != nil {
		log.Error("verifysign error is %s", verify_err)
		res = false
		return res, verify_err
	} else {
		return res, err
	}
}

//写文件
func writefile(cert string, path string) (err error) {
	fileName := path
	dstFile, err := os.Create(fileName)
	if err != nil {
		log.Debugf(err.Error())
		return
	}
	defer dstFile.Close()
	s := cert
	dstFile.WriteString(s)
	return
}

/*
//对字符串进行MD5哈希
func a(data string) string {
	t := md5.New()
	io.WriteString(t, data)
	return fmt.Sprintf("%x", t.Sum(nil))
}
*/

//对字符串进行SHA256哈希
func Sha256(data string) string {
	t := sha256.New()
	io.WriteString(t, data)
	return fmt.Sprintf("%x", t.Sum(nil))
}

//读取文件
func Readfile(filePth string) (s string, err error) {
	b, err_readfile := ioutil.ReadFile(filePth)
	if err_readfile != nil {
		log.Debugf("read file occur err %s", err_readfile)
		return string(b), err
	}
	//log.Debugf(b)
	str1 := string(b)
	return str1, err
	//log.Debugf(str)
}

//获取所有文件带后缀
func getallfileWithSuffix(s_dir string) []string {
	dir, error := os.OpenFile(s_dir, os.O_RDONLY, os.ModeDir)
	if error != nil {
		defer dir.Close()
		return nil
	}
	names, _ := dir.Readdir(-1)
	var allfile []string
	for _, name := range names {
		filenameWithSuffix := path.Base(name.Name())
		allfile = append(allfile, filenameWithSuffix)
	}
	return allfile
}

//编码
func b64Encode(src []byte) string {
	//return []byte(coder.EncodeToString(src))
	return base64.StdEncoding.EncodeToString(src)
	//base64.NewEncoding(base64Table)
}

// base64解码
func b64decode(encodeString string) (string, error) {
	s := ""
	var err error
	decodeBytes, b64decode_err := base64.StdEncoding.DecodeString(encodeString)
	if b64decode_err != nil {
		log.Error("b64decode occur err is %s", b64decode_err)
		return s, b64decode_err
	}
	s = string(decodeBytes)
	return s, err

}

//删除文件
func Delfile(filepath string) error {

	file := filepath //文件路径
	var err error
	for i := 0; i < 2; i++ {
		err := os.Remove(file)
		if err != nil {
			//如果删除失败则输出 file remove Error!
			log.Debugf("file remove Error!")
			//输出错误详细信息
			log.Debugf("%s", err)
			continue
		} else {
			//如果删除成功则输出 file remove OK!
			log.Debugf("file remove OK!")
			break
		}

	}
	return err

}

//进行zlib压缩
func DoZlibCompres(src []byte) []byte {
	var in bytes.Buffer
	w := zlib.NewWriter(&in)
	w.Write(src)
	w.Close()
	return in.Bytes()
}

//进行zlib解压缩
func DoZlibUnCompres(compressSrc []byte) []byte {
	b := bytes.NewReader(compressSrc)
	var out bytes.Buffer
	r, _ := zlib.NewReader(b)
	io.Copy(&out, r)
	return out.Bytes()
}

func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}

func getallfile(s_dir string) []string {
	dir, error := os.OpenFile(s_dir, os.O_RDONLY, os.ModeDir)
	if error != nil {
		defer dir.Close()
		return nil
	}
	names, _ := dir.Readdir(-1)
	var allfile []string
	for _, name := range names {
		filenameWithSuffix := path.Base(name.Name())
		fileSuffix := path.Ext(filenameWithSuffix)
		filenameOnly := strings.TrimSuffix(filenameWithSuffix, fileSuffix)
		allfile = append(allfile, filenameOnly)
	}
	sort.Strings(allfile)
	//fmt.Println("all file  is ", RemoveDuplicatesAndEmpty(allfile))
	Allfile := RemoveDuplicatesAndEmpty(allfile)
	return Allfile
}

//判断字符串是否存在于文件中
func judge(array []string, str string) bool {

	sum := 1
	for _, value := range array {

		if str == value {
			break
		}
		sum += 1
		continue
	}
	if sum > len(array) {
		return false
	} else {
		return true
	}

}

//拷贝文件
func CopyFile(dstName, srcName string) (written int64, err error) {
	src, err := os.Open(srcName)
	if err != nil {
		return
	}
	defer src.Close()
	dst, err := os.OpenFile(dstName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer dst.Close()
	return io.Copy(dst, src)
}

//结构体转为map型
func Struct2Map(obj interface{}) map[string]interface{} {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)

	var data = make(map[string]interface{})
	for i := 0; i < t.NumField(); i++ {
		data[t.Field(i).Name] = v.Field(i).Interface()
	}
	return data
}

//一行一行读取一个文件
func Readline(file string) string {
	var lines string
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n') //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			break
		}
		lines += line
	}
	return lines
}

//获取指定目录下的所有文件，不进入下一级目录搜索，可以匹配后缀过滤
func ListDir(dirPth string, suffix string) (files []string, err error) {
	files = make([]string, 0, 10)
	dir, err := ioutil.ReadDir(dirPth)
	if err != nil {
		return nil, err
	}
	PthSep := string(os.PathSeparator)
	suffix = strings.ToUpper(suffix) //忽略后缀匹配的大小写
	for _, fi := range dir {
		if fi.IsDir() { // 忽略目录
			continue
		}
		if strings.HasSuffix(strings.ToUpper(fi.Name()), suffix) { //匹配文件
			files = append(files, dirPth+PthSep+fi.Name())
		}
	}
	return files, nil
}

//
func Judgestrexitinfile(filepath string, str string) bool {

	var res bool
	res = false
	files, err := ListDir(filepath, ".conf")
	if err != nil {
		log.Debugf("listDir occur err %s", err.Error())
	} //fmt.Println(files)
	for _, f := range files {
		var t bool
		strfile := Readline(f)
		t = strings.Contains(strfile, str)
		if t == true {
			res = true
			break
		} else {
			continue
		}
	}
	return res

}

func Transferfile(data TransferInfo, ch1 chan TransfeResult) {

	var status int
	o_path_allfile := getallfileWithSuffix(data.o_path)
	d_path_allfile := getallfileWithSuffix(data.d_path)
	file_exits_opath := judge(o_path_allfile, data.save_name+"."+data.form)
	log.Debugf("file_exits_opath result is %t", file_exits_opath)
	file_exits_dpath := judge(d_path_allfile, data.save_name+"."+data.form)
	log.Debugf("file_exits_dpath result is %t", file_exits_dpath)
	//filename := data.save_name + "." + data.form
	if file_exits_dpath == false && file_exits_opath == false {
		status = 504
		ch1 <- TransfeResult{status, data.save_name, data.form}
		return
	} else {
		if file_exits_opath == true {
			filename := data.save_name + "." + data.form
			file_opath, err_readfile := Readfile(data.o_path + filename)
			if err_readfile != nil {
				log.Debugf("read file occur err %s", err_readfile)
				status = 511
				ch1 <- TransfeResult{status, data.save_name, data.form}
				return
			}
			sha256_file_opath := Sha256(file_opath)
			_, err_copyfile := CopyFile(data.d_path+filename, data.o_path+filename)
			if err_copyfile != nil {
				log.Debugf("copy file occur err %s", err_copyfile)
				copy_delf_err := Delfile(data.d_path + filename)
				if copy_delf_err != nil {
					log.Error("after copy del failed file occur err  %s", copy_delf_err.Error())
					status = 512
					ch1 <- TransfeResult{status, data.save_name, data.form}
					return
				}
				status = 513
				ch1 <- TransfeResult{status, data.save_name, data.form}
				return

			}

			file_dpath, err_readfile_dpath := Readfile(data.d_path + filename)
			if err_readfile_dpath != nil {
				log.Debugf("read file dpath occur err %s", err_readfile_dpath)
				err_readfile_delc := Delfile(data.d_path + filename)
				if err_readfile_delc != nil {
					log.Error("copy failed del file occur err  %s", err_readfile_delc.Error())
					status = 514
					ch1 <- TransfeResult{status, data.save_name, data.form}
					return
				}
				status = 515
				ch1 <- TransfeResult{status, data.save_name, data.form}
				return
			}
			sha256_file_dpath := Sha256(file_dpath)
			if sha256_file_opath == sha256_file_dpath {

				err_delfile := Delfile(data.o_path + filename)
				if err_delfile != nil {
					log.Debugf("sha256 comparison success del file occur err %s", err_delfile)
					status = 516
					ch1 <- TransfeResult{status, data.save_name, data.form}
					return
				}

				status = 200
				ch1 <- TransfeResult{status, data.save_name, data.form}
				log.Debugf("transfer %s file task success!!!", data.form)
				return
			} else {

				err_sha256_delfile := Delfile(data.d_path + filename)

				if err_sha256_delfile != nil {
					log.Debugf("sha256 comparison failed del file occur err %s", err_sha256_delfile)
					status = 518
					ch1 <- TransfeResult{status, data.save_name, data.form}
					return
				}
				status = 519
				ch1 <- TransfeResult{status, data.save_name, data.form}
				return

			}
		} else {

			status = 200
			ch1 <- TransfeResult{status, data.save_name, data.form}
			return

		}
	}

}

func ResultReport(certstatus int, keystatus int, savename string) int {

	//res := make(map[string]int)
	var res int
	if certstatus == 200 && keystatus == 200 {
		//res[strings.Replace(savename, ".", "%", -1)] = 200 //证书和私钥转移成功
		res = 200
	} else if certstatus == 200 && keystatus != 200 {
		//res[strings.Replace(savename, ".", "%", -1)] = 201 //证书转移成功
		res = 201
	} else if keystatus == 200 && certstatus != 200 {
		//res[strings.Replace(savename, ".", "%", -1)] = 202 //私钥转移成功
		res = 202
	} else {
		//res[strings.Replace(savename, ".", "%", -1)] = 505 //异常
		res = 505
	}
	return res

}

//执行转移文件任务
func TransferTask(data TransdataFromCenter, ch chan TransferpostData) {

	//var status int
	o_path := data.O_path
	d_path := data.D_path
	task_id := data.Task_id
	s_name := data.Save_name
	res := make(map[string]int)

	//var transferpostdata TransferpostData
	array_s_name := strings.Split(s_name, ",")

	var Messa []TransfeResult
	ch1 := make(chan TransfeResult)
	for _, save_name := range array_s_name {

		transfercertinfo := TransferInfo{o_path, d_path, "crt", save_name, task_id}
		transferkeyinfo := TransferInfo{o_path, d_path, "key", save_name, task_id}

		go Transferfile(transfercertinfo, ch1)
		go Transferfile(transferkeyinfo, ch1)
		//keystatus := Transferfile(transferkeyinfo)

	}
	for i := 0; i < 2*len(array_s_name); i++ {
		r := <-ch1
		//log.Debugf("res is %s", string(res))
		Messa = append(Messa, r)

	}
	for _, savename := range array_s_name {
		var certstatus int
		var keystatus int
		for j := 0; j < len(Messa); j++ {

			if Messa[j].save_name == savename {

				if Messa[j].form == "crt" {
					certstatus = Messa[j].status
					log.Debugf("cert status is %d", certstatus)
				} else if Messa[j].form == "key" {
					keystatus = Messa[j].status
					log.Debugf("key status is %d", keystatus)
				}
			}
		}
		res[strings.Replace(savename, ".", "%", -1)] = ResultReport(certstatus, keystatus, savename)
	}

	log.Debugf("Messa is %+v", Messa)
	log.Debugf("res is %+v", res)
	transferdata := TransferpostData{200, res, task_id}
	ch <- transferdata
	return

}

//获取文件信息
func Getfileinfo(path string, save_name string, config_path string, file_type string) map[string]interface{} {

	var res = make(map[string]interface{})
	strfile := path + "/" + save_name + "." + file_type
	all_files_path := getallfileWithSuffix(path)
	file_exits_path := judge(all_files_path, save_name+"."+file_type)
	if file_type == "crt" || file_type == "cer" {
		var certinfo QuerycertInfo
		if file_exits_path == false {

			certinfo.Cert_exit = false
			certinfo.Cert_type = file_type
		} else {

			filemode, file_err := os.Stat(strfile)
			if file_err != nil {
				log.Debugf("open file occur error %s", file_err)
			}
			filesize := filemode.Size()
			filemodtime := filemode.ModTime()
			filecontent, err_read_file := ioutil.ReadFile(strfile)
			if err_read_file != nil {

				log.Debugf("read file occur exception %s", err_read_file.Error())
			}
			certinfo.Sha256cert = Sha256(string(filecontent))
			certinfo.Cert_exit = true
			certinfo.Cert_info = strconv.FormatInt(filesize, 10) + "\n" + strings.Split(filemodtime.String(), ".")[0]
			certinfo.Cert_exitinconf = Judgestrexitinfile(config_path, save_name+"."+file_type)
			certinfo.Cert_type = file_type
		}
		res = Struct2Map(certinfo)
		log.Debugf("cert res is %+v", res)
		return res

	} else {

		var keyinfo QuerykeyInfo
		if file_exits_path == false {

			keyinfo.Key_exit = false
		} else {

			filemode, _ := os.Stat(strfile)
			filesize := filemode.Size()
			filemodtime := filemode.ModTime()
			filecontent, err_read_file := ioutil.ReadFile(strfile)
			if err_read_file != nil {

				log.Debugf("read file occur exception %s", err_read_file.Error())
			}
			keyinfo.Sha256key = Sha256(string(filecontent))
			keyinfo.Key_exit = true
			keyinfo.Key_info = strconv.FormatInt(filesize, 10) + "\n" + strings.Split(filemodtime.String(), ".")[0]
			keyinfo.Key_exitinconf = Judgestrexitinfile(config_path, save_name+"."+file_type)
		}
		res = Struct2Map(keyinfo)
		log.Debugf("key res is %+v", res)
		return res
	}
}

//处理查询文件的任务
func QueryfileTask(data QuerydataFromCenter, ch chan QuerypostData) {

	query_path := data.Query_path
	query_cert_name := data.Query_cert_name
	query_cert_type := data.Query_cert_type
	log.Debugf("cert type is %s", query_cert_type)
	task_id := data.Task_id
	query_config_path := data.Query_config_path
	res_cert := Getfileinfo(query_path, query_cert_name, query_config_path, query_cert_type)
	res_key := Getfileinfo(query_path, query_cert_name, query_config_path, "key")
	log.Debugf("res_cert is %+v", res_cert)
	log.Debugf("res_key is %+v", res_key)
	info := make(map[string]interface{})
	info["cert_name"] = query_cert_name
	info["cert_exit"] = res_cert["Cert_exit"]
	info["cert_type"] = res_cert["Cert_type"]
	info["cert_info"] = res_cert["Cert_info"]
	info["key_exit"] = res_key["Key_exit"]
	info["key_info"] = res_key["Key_info"]
	info["sha256cert"] = res_cert["Sha256cert"]
	info["sha256key"] = res_key["Sha256key"]
	info["cert_exitinconf"] = res_cert["Cert_exitinconf"]
	info["key_exitinconf"] = res_key["Key_exitinconf"]
	res := QuerypostData{200, info, task_id}
	ch <- res
	return
	//strcert := querypath + query_cert_name + ".crt"
	//strkey := querypath + query_cert_name + ".key"

}

//执行写入证书任务
func SavefileTask(data DataFromCenter, ch chan string) {

	var status int
	var certfile string
	cert := data.Cert
	var cert_s256 string
	//log.Debugf(cert_s256)
	key := data.P_key
	task_id := data.Task_id
	cert_type := data.Cert_type
	//log.Debugf("cert_type is %s", cert_type)
	cert_clipher_wen, cert_sign := cert[0:len(cert)-344], cert[len(cert)-344:len(cert)]
	key_clipher_wen, key_sign := key[0:len(key)-344], key[len(key)-344:len(key)]
	s_dir := data.S_dir
	save_name := data.S_name
	c_sign, c_sign_b64decode_err := b64decode(cert_sign)
	if c_sign_b64decode_err != nil {
		log.Debugf(" cert_sign b64decode occur err %s", c_sign_b64decode_err)
		status = 512
		ch <- strconv.Itoa(status) + task_id
		return
	}
	//log.Debugf(" c_sign_b64decode_err is %s", c_sign_b64decode_err)
	k_sign, k_sign_b64decode_err := b64decode(key_sign)
	if k_sign_b64decode_err != nil {
		log.Debugf("key_sign b64decodec occur err %s", k_sign_b64decode_err)
		status = 513
		ch <- strconv.Itoa(status) + task_id
		return
	}

	c_cli_wen, cert_b64decode_err := b64decode(cert_clipher_wen)
	if cert_b64decode_err != nil {
		log.Error("cert b64decode occur err %s", cert_b64decode_err.Error())
		status = 514
		ch <- strconv.Itoa(status) + task_id
		return
	}
	k_cli_wen, key_b64decode_err := b64decode(key_clipher_wen)
	if key_b64decode_err != nil {
		log.Error("key b64decode err is %s", key_b64decode_err.Error())
		status = 515
		ch <- strconv.Itoa(status) + task_id
		return
	}
	seed := data.Seed
	var cert_cli_wen string
	var key_cli_wen string

	if seed == "" {
		cert_cli_wen = c_cli_wen
		key_cli_wen = k_cli_wen
	} else {
		cert_cli_wen = deal(c_cli_wen, seed)
		key_cli_wen = deal(k_cli_wen, seed)
	}
	//log.Debugf("cert_cli_wen is %s\n", cert_cli_wen)
	//log.Debugf("key_cli_wen is %s\n", key_cli_wen)

	var err_read_prikey error
	privateKey, err_read_prikey = ioutil.ReadFile("private_2048.pem")
	//fmt.Println(len(string(privateKey)))
	if err_read_prikey != nil {

		log.Debugf("read prikey occur err %s", err_read_prikey.Error())
		status = 516
		ch <- strconv.Itoa(status) + task_id
		return

	}

	var err_read_pubkey error
	pub_key, err_read_pubkey = ioutil.ReadFile("public_2048.pem")
	if err_read_pubkey != nil {

		log.Debugf("read pubkey occur err %s", err_read_pubkey.Error())
		status = 517
		ch <- strconv.Itoa(status) + task_id
		return
	}

	cert_m_wen, cert_decrypt_err := decrypt_trunk(cert_cli_wen, string(privateKey))

	if cert_decrypt_err != nil {

		log.Debugf("cert decrypt occur err %s", cert_decrypt_err.Error())
		status = 518
		ch <- strconv.Itoa(status) + task_id
		return
	}
	//cert_s256 = b(cert_m_wen)
	cert_verify_result, cert_verify_err := verify_sign(c_sign, string(pub_key), cert_m_wen)
	if cert_verify_err != nil {
		log.Debugf("cert verify occur err %s", cert_verify_err.Error())
		log.Debugf("cert verify result is %t", cert_verify_result)
		status = 519
		ch <- strconv.Itoa(status) + task_id
		return
	}
	cert_s256 = Sha256(cert_m_wen)

	key_m_wen, key_decrypt_err := decrypt_trunk(key_cli_wen, string(privateKey))
	key_s256 := Sha256(key_m_wen)
	if key_decrypt_err != nil {
		log.Error("key decrypt occur err %s", key_decrypt_err.Error())
		status = 520
		ch <- strconv.Itoa(status) + task_id
		return
	}
	key_verify_result, key_verify_err := verify_sign(k_sign, string(pub_key), key_m_wen)
	if key_verify_err != nil {
		log.Error("key verify occur err is %s", key_verify_err.Error())
		log.Debugf("key verify result is %t", key_verify_result)
		status = 521
		ch <- strconv.Itoa(status) + task_id
		return
	}
	if cert_type != "" {
		certfile = s_dir + "/" + save_name + cert_type
	}
	certfile = s_dir + "/" + save_name + ".crt"
	var i int
	for i := 0; i < 2; i++ {
		writecert_err := writefile(cert_m_wen, certfile)
		if writecert_err == nil {
			//log.Debugf("writecert_err is %s", writecert_err.Error())
			//status = 518
			//ch <- status
			break
		}
		w_delc_err := Delfile(certfile)
		if w_delc_err != nil {
			log.Error("w_del cert occur err  %s", w_delc_err.Error())
			status = 522
			ch <- strconv.Itoa(status) + task_id
			return
		}
	}
	if i >= 2 {
		status = 523
		ch <- strconv.Itoa(status) + task_id
		return
		//writefile(cert, keyfile)
	}
	c, readcert_err := Readfile(certfile)
	if readcert_err != nil {
		readcert_del_err := Delfile(certfile)
		if readcert_del_err != nil {
			log.Error("readcert del occur err  %s", readcert_del_err.Error())
			status = 524
			ch <- strconv.Itoa(status) + task_id
			return
		}

		status = 525
		ch <- strconv.Itoa(status) + task_id
		return
	}

	//log.Debugf("c is || e10 is", len(c), e10)
	//log.Debugf("cert is", len(cert))

	cert_sha256 := Sha256(c)
	//log.Debugf("cert_sha256 is", cert_sha256)
	if cert_s256 != cert_sha256 {
		s256_del_err := Delfile(certfile)
		if s256_del_err != nil {
			log.Error(" s256 del occur err %s", s256_del_err.Error())
			status = 526
			ch <- strconv.Itoa(status) + task_id
			return
		}
		status = 527
		ch <- strconv.Itoa(status) + task_id
		return
	}

	keyfile := s_dir + "/" + save_name + ".key"
	var j int
	for j = 0; j < 2; j++ {
		writekey_err := writefile(key_m_wen, keyfile)
		if writekey_err == nil {
			//log.Error("write key error is %s", writekey_err.Error())
			break
		}
		writekey_del_k_err := Delfile(keyfile)
		writekey_del_c_err := Delfile(certfile)
		if writekey_del_c_err != nil || writekey_del_k_err != nil {
			log.Error(" write_del_c err is %s||write_del_k err is %s", writekey_del_c_err.Error(), writekey_del_k_err.Error())
			status = 528
			ch <- strconv.Itoa(status) + task_id
			return
		}
	}
	if j >= 2 {
		status = 529
		ch <- strconv.Itoa(status) + task_id
		return
	}
	k, readkey_err := Readfile(keyfile)
	if readkey_err != nil {

		readkey_del_key_err := Delfile(keyfile)
		readkey_del_cert_err := Delfile(certfile)
		if readkey_del_cert_err != nil || readkey_del_key_err != nil {
			status = 530
			log.Error(" readkey_del_cert_err is %s||readkey_del_key_err is %s", readkey_del_cert_err.Error(), readkey_del_key_err.Error())
			ch <- strconv.Itoa(status) + task_id
			return
		}
		status = 531
		ch <- strconv.Itoa(status) + task_id
		return
	}
	//log.Debugf("k is || e13 is", len(k), e13)
	//log.Debugf("len(key) is", len(key))
	key_sha256 := Sha256(k)
	//log.Debugf("key_sha256 is", key_sha256)
	if key_s256 != key_sha256 {
		key_s256_del_err := Delfile(keyfile)
		cert_s256_del_err := Delfile(certfile)
		if cert_s256_del_err != nil || key_s256_del_err != nil {
			status = 532
			log.Error(" cert_s256_del_err is %s||key_s256_del_err is %s", cert_s256_del_err.Error(), key_s256_del_err.Error())
			ch <- strconv.Itoa(status) + task_id
			return
		}
		status = 533
		ch <- strconv.Itoa(status) + task_id
		return
	}
	status = 200
	os.Chmod(keyfile, 0777)
	os.Chmod(certfile, 0777)
	ch <- strconv.Itoa(status) + task_id
	return

}

func main() {

	router := mux.NewRouter()
	//router.HandleFunc("/cert/pull")
	router.HandleFunc("/", TaskRequestPost).Methods("POST")
	router.HandleFunc("/cert/pull", TaskPost).Methods("get")
	router.HandleFunc("/cert/day/pull", TaskPostday).Methods("get")
	router.HandleFunc("/transfer_cert", TransferRequestPost).Methods("POST")
	router.HandleFunc("/checkcertisexits", QueryRequestPost).Methods("POST")
	log.Printf("Starting on port: %d", serverPort)
	if errServer := http.ListenAndServe(fmt.Sprintf(":%d", serverPort), router); errServer != nil {
		log.Printf("FatalError: main errServer: %s", errServer)
	}
	fmt.Println(CENTERIPLIST)

}
