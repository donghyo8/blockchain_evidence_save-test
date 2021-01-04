package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	// "github.com/labstack/echo"
	// "net/http"
)

/* ===================================== Blockchain Conf. ===================================== */

const difficulty = 0

var Blockchain []Block
var mutex = &sync.Mutex{}

type Block struct {
	Index          int    // 데이터 레코드의 위치
	Timestamp      string // 데이터 작성 시 시간
	Transaction    int    // Beats Per Minute: pulse rate
	Hash           string // SHA256을 이용하여 데이터 레코드를 식별
	PrevHash       string // 이전 데이터 레코드의 Hash를 의미
	Difficulty     int
	Nonce          string
	Video_Evidence []byte // Vedio Evidence raw data (Binary)
}

type Message struct {
	Transaction    int
	Video_Evidence []byte
}

/*
   - 블록에 대한 SHA256 해시를 생성하는 함수
    블록의 Index, Timestamp, Transaction, PrevHash를 연결하여 하나의 레코드로 만듬
	이후, 레코드를 SHA256으로 해시화 한 후 문자열 형태의 해시 값으로 반환
*/
func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + strconv.Itoa(block.Transaction) + block.PrevHash + block.Nonce /* + string(block.Vedio_Evidence) */
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

/*
   - 해쉬 값 검증(POW)

*/
func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

/*
   - 블록을 생성하는 함수
	이 함수가 실행되기 위해서는 이전 블록에 대한 정보가 필요
	PrevHash 가 있어야 블록의 해시를 계산할 수 있으며, 파라미터 값으로 Transaction을 받아야함
*/
func generateBlock(oldBlock Block, Transaction int, Video_Evidence []byte) Block {

	var newBlock Block

	t := time.Now().Format("2006-01-02 15:04:05")

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t
	newBlock.Transaction = Transaction
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)
	newBlock.Difficulty = difficulty
	newBlock.Video_Evidence = Video_Evidence

	for i := 0; ; i++ {
		hex := fmt.Sprintf("%x", i)
		newBlock.Nonce = hex
		if !isHashValid(calculateHash(newBlock), newBlock.Difficulty) {
			fmt.Println(calculateHash(newBlock), "------> Consensus ... ") // sleep status
			time.Sleep(time.Second)
			continue
		} else {
			fmt.Println(calculateHash(newBlock), "------> Create Block Success !!! ") // success
			newBlock.Hash = calculateHash(newBlock)
			break
		}

	}

	return newBlock
}

/*
   - 블록 유효성 검사
	1. Index를 확인함으로써 연속적으로 증가했는지 확인
	2. Prevhash가 이전 블록의 hash와 같은지 확인
	3. calculatehash를 재호출하여 현재 블록에 해쉬를 확인하고 블록에 이상이 없는지 확인
*/
func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

/*
   - 체인 길이 비교
	두개의 노드에서 체인의 길이가 다르기 때문에 더 긴 체인에 생성된 블록 추가
	현재 체인 보다 새롭게 생성된 체인 쪽 길이가 더 큰게 맞으면 현재 블록에 덮어 씌움
*/
func replaceChain(newBlocks []Block) {
	if len(newBlocks) > len(Blockchain) {
		Blockchain = newBlocks
	}
}

/* ===================================== Server Conf. ===================================== */

/*
   - POST reuqest는 Transaction을 담을 구조체 필요
*/
func run() error {
	mux := makeMuxRouter()
	httpAddr := os.Getenv("ADDR")
	log.Println("======================= Listening on ", os.Getenv("ADDR =======================\n"))
	s := &http.Server{
		Addr:           ":" + httpAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

/*
   - 핸들러 정의를 위한 makeMuxRouter 함수
	브라우저에서 블록체인을 보고 블록을 생성하기 위해 2개의 route가 필요
	1. GET request를 서버에 보내면 브라우저를 통해 블록체인을 확인 가능
	2. POST reuqest를 보내면 블록 생성
*/

func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	// muxRouter.HandleFunc("/", homeLink)
	// muxRouter.HandleFunc("/file", UploadFile).Methods("POST")
	// log.Fatal(http.ListenAndServe(":3500", muxRouter))

	return muxRouter
}

/*
   - GET 핸들러 함수 (블록 조회)
    .env에 정의한 포트로 접속 가능
*/
func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, string("======================= Block Info. =======================\n\n"))
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}

/*
   - POST 핸들러 함수 (블록 추가)
	POST request를 이용하여 새 블록을 생성
	spew.Dump는 콘솔에 찍어주기 위한 함수
*/
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var m Message

	r.ParseMultipartForm(10 << 50) // 최대 메모리 크기 설정

	if r.Method == "POST" {
		file, handler, err := r.FormFile("file") // 파일 획득

		if err != nil {
			fmt.Println("Error Retrieving file from form-data")
			fmt.Println(err)
			return
		}

		defer file.Close()

		println()
		println("======================= Video_Evidence & Transaction Info. 				=======================\n")
		println("Video_Evidence Name: ", handler.Filename)
		fmt.Println("Video_Evidence Size: ", float64(int64(handler.Size/1000000))/1000, "GB")
		println("Video_Evidence Header: ", handler.Header)
		println("Transaction: ", m.Transaction)
		println()

		tempFile, err := ioutil.TempFile("original-data", "upload-Video_*.mp4")
		errCheck(err)

		defer tempFile.Close()

		fileBytes, err := ioutil.ReadAll(file)
		errCheck(err)

		// tempFile.Write(fileBytes) // 디렉토리 내 파일 저장
		fmt.Fprintf(w, "Successfully file Upload")
		f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		errCheck(err)
		defer f.Close()

		io.Copy(f, file) //파일 시스템 파일 저장

		/* File Raw Data Print
		var arr []byte
		arr, err = ioutil.ReadFile("./vedio/test2.mp4")
		// var length int
		// length = len(arr)
		fmt.Print(arr)
		ioutil.WriteFile("./encodingInfo/binary.mp4", []byte(arr), os.FileMode(644))
		*/

		decoder := json.NewDecoder(r.Body)
		//encoder := b64.StdEncoding.EncodeToString([]byte(fileBytes))

		if err := decoder.Decode(&m); err != nil {
			if err := m.Video_Evidence; err != nil {
				respondWithJSON(w, r, http.StatusBadRequest, r.Body)
				return
			}
		}
		defer r.Body.Close()

		//binaryInfo := ioutil.WriteFile("./data_info/binary_result.txt", []byte(fileBytes), os.FileMode(644))
		//errCheck(binaryInfo)
		//encodingInfo := ioutil.WriteFile("./data_info/encoidng_result.txt", []byte(encoder), os.FileMode(644))
		//errCheck(encodingInfo)

		println("======================= Mutex Lock =======================\n")
		mutex.Lock()
		println()
		newBlock := generateBlock(Blockchain[len(Blockchain)-1], m.Transaction, []byte(fileBytes))
		mutex.Unlock()
		println("\n======================= Mutex UnLock =======================\n")

		println("======================= Block Info. =======================\n")

		if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
			Blockchain = append(Blockchain, newBlock)
			spew.Dump(Blockchain)
		}

		// fmt.Println(newBlock)

		respondWithJSON(w, r, http.StatusCreated, newBlock)

		println()
		println("======================= Block Wait ... =======================\n")

	} else {
		fmt.Println("Unknown HTTP " + r.Method + "  Method")
	}

}

/*
   - POST 메시지 확인 함수
*/
func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response, err := json.MarshalIndent(payload, "", "")

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.Write(response)
}

func errCheck(e error) {
	if e != nil {
		fmt.Println(e)
		return
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		t := time.Now().Format("2006-01-02 15:04:05")
		genesisBlock := Block{}
		genesisBlock = Block{0, t, 0, calculateHash(genesisBlock), "", difficulty, "", []byte{8}}
		spew.Dump(genesisBlock)
		mutex.Lock()
		Blockchain = append(Blockchain, genesisBlock)
		mutex.Unlock()
	}()
	log.Fatal(run())

}
