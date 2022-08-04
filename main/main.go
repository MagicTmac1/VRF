package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

func main() {
	con := jichen(256)
	GenerateEccKey()
	src := []byte("使用x509对pem.Block中的Bytes变量中的数据进行解析 ->  得到一接口")
	rText, sText := EccSignature(src, "eccPrivate.pem")
	bl := EccVerify(src, rText, sText, "eccPublic.pem")
	fmt.Println(bl)
	pub := ReadPub("eccPublic.pem")
	a, _, _ := hash2bin(GetSHA256HashCode(pub)) //a为公钥hash
	num := bin2BigFloat(a)
	result := con.Quo(num, con)
	fmt.Println(result)
}

//二进制转化成big.Float
func bin2BigFloat(s string) *big.Float {
	l := len(s)
	num, _ := new(big.Float).SetString("0")
	for i := l - 1; i >= 0; i-- {
		if s[i] != '0' {
			num = num.Add(num, jichen(l-1-i))
		}
	}
	return num
}

//2的n阶乘
func jichen(n int) *big.Float {
	two, _ := new(big.Float).SetString("2")
	num, _ := new(big.Float).SetString("1")
	for i := 0; i < n; i++ {
		num = num.Mul(num, two)
	}
	return num
}

// 1. 生成密钥对
func GenerateEccKey() {
	//1. 使用ecdsa生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//fmt.Println(privateKey.Y, privateKey.Y, privateKey.D)
	if err != nil {
		panic(err)
	}
	//2. 将私钥写入磁盘
	//- 使用x509进行序列化
	derText, err := x509.MarshalECPrivateKey(privateKey)
	//sha256.New()
	if err != nil {
		panic(err)
	} //返回私钥
	//- 将得到的切片字符串放入pem.Block结构体中
	block := pem.Block{
		Type:  "ecdsa private key",
		Bytes: derText,
	}
	//- 使用pem编码
	file, err := os.Create("eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
	//3. 将公钥写入磁盘
	//- 从私钥中得到公钥
	publicKey := privateKey.PublicKey
	//- 使用x509进行序列化
	derText, err = x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//- 将得到的切片字符串放入pem.Block结构体中
	block = pem.Block{
		Type:  "ecdsa public key",
		Bytes: derText,
	}
	//- 使用pem编码
	file, err = os.Create("eccPublic.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
}

// ecc签名 - 私钥
func EccSignature(plainText []byte, privName string) (rText, sText []byte) {
	//1. 打开私钥文件, 将内容读出来 ->[]byte
	file, err := os.Open(privName)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2. 使用pem进行数据解码 -> pem.Decode()
	block, _ := pem.Decode(buf)

	//3. 使用x509, 对私钥进行还原
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 对原始数据进行哈希运算 -> 散列值
	hashText := sha1.Sum(plainText)
	//5. 进行数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
	if err != nil {
		panic(err)
	}
	// 6. 对r, s内存中的数据进行格式化 -> []byte
	rText, err = r.MarshalText()
	if err != nil {
		panic(err)
	}
	sText, err = s.MarshalText()
	if err != nil {
		panic(err)
	}
	return
}

// ecc签名认证
func EccVerify(plainText, rText, sText []byte, pubFile string) bool {
	//1. 打开公钥文件, 将里边的内容读出 -> []byte
	file, err := os.Open(pubFile)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2. pem解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	//3. 使用x509对公钥还原
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4. 将接口 -> 公钥
	publicKey := pubInterface.(*ecdsa.PublicKey)

	//5. 对原始数据进行哈希运算 -> 得到散列值
	hashText := sha1.Sum(plainText)
	// 将rText, sText -> int数据
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	//6. 签名的认证 - > ecdsa  (问题,api的设计为什么在这个地方要传地址,直接传值比较不是更好吗?)
	bl := ecdsa.Verify(publicKey, hashText[:], &r, &s)
	return bl
}

//将
func GetSHA256HashCode(message []byte) string {
	//方法一：
	//创建一个基于SHA256算法的hash.Hash接口的对象
	hash := sha256.New()
	//输入数据
	hash.Write(message)
	//计算哈希值
	bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(bytes)
	//返回哈希值,64*4=256
	return hashCode

	//方法二：
	//bytes2:=sha256.Sum256(message)//计算哈希值，返回一个长度为32的数组
	//hashcode2:=hex.EncodeToString(bytes2[:])//将数组转换成切片，转换成16进制，返回字符串
	//return hashcode2
}

func hash2bin(hash string) (string, int, error) {
	binary_string := ""
	for _, char := range hash {
		char_hex, err := strconv.ParseInt(string(char), 16, 8)
		if err != nil {
			return "", 0, err
		}
		char_bin := ""
		for ; char_hex > 0; char_hex /= 2 {
			b := char_hex % 2
			char_bin = strconv.Itoa(int(b)) + char_bin
		}
		fill := 4 - len(char_bin)
		for fill > 0 {
			char_bin = "0" + char_bin
			fill -= 1
		}
		binary_string += char_bin
	}
	return binary_string, len(binary_string), nil
}

//读取公钥
func ReadPub(pubFile string) []byte {
	file, err := os.Open(pubFile)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2. pem解码 -> pem.Decode()
	block, _ := pem.Decode(buf)
	return block.Bytes
}
