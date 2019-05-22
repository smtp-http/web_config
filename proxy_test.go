package top

import (
	"testing"
)

func TestIsValidIP(t *testing.T) {
	valid := isValidIP("172.17.208.48")
	if valid != true {
		t.Fatalf("%v is %v", "172.17.208.48", valid)
	}
	valid = isValidIP("172.17.208")
	if valid != false {
		t.Fatalf("%v is %v", "172.17.208", valid)
	}
	valid = isValidIP("172.17.256.1")
	if valid != false {
		t.Fatalf("%v is %v", "172.17.256.1", valid)
	}
	valid = isValidIP("199.17.208.1")
	if valid != true {
		t.Fatalf("%v is %v", "199.17.208.1", valid)
	}
	valid = isValidIP("172.17.208.a")
	if valid != false {
		t.Fatalf("%v is %v", "172.17.208.a", valid)
	}
}

func TestCheckAuth(t *testing.T) {
	isAdmin := CheckAuth("MkXQyvljj8FSeQq_2BrNtY5256ZCL4D3nvP9oWvHKOygU_3D", "11", "133", "60")
	if !isAdmin {
		t.Fatalf("%v is %v", "60", isAdmin)
	}
	isAdmin = CheckAuth("MkXQyvljj8FSeQq_2BrNtY5256ZCL4D3nvP9oWvHKOygU_3D", "11", "133", "61")
	if isAdmin {
		t.Fatalf("%v is %v", "61", isAdmin)
	}
}

func GetTopProxy(t *testing.T) *TopProxy {
	return &TopProxy{
		JSONConfigAddr: "C:/Users/admin/Desktop/test.json",
	}
}

func TestLoadConfig(t *testing.T) {
	tp := GetTopProxy(t)
	config, code := tp.LoadJSONConfig("")
	t.Log(config, code)
}

func TestPath(t *testing.T) {
	// t.Fatal(strings.Replace("/data/path", filepath.Base("/data/path"), "", 1))
	var i uint64
	i = 5366087680000
	t.Log(i)
	t.Log(int64(i))
}
