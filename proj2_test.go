package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")
	userlib.SetDebugStatus(true)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Init Failed.", err)
		return
	}
	_ = u
}

func TestInit2(t *testing.T) {
	userlib.SetDebugStatus(true)
	clear()
	t.Log("Initialization test")
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("InitUser Error", err)
	}
	_ = u1
	u2, err := InitUser("Lebron", "fubar")
	if err != nil {
		t.Error("InitUser Error", err)
	}
	_ = u2
	// Check that Lebron was initialized correctly
	BronClone1, err := GetUser("Lebron", "fubar")
	if err != nil {
		t.Error("Get User Failed", err)
	}
	BronClone2, _ := GetUser("Lebron", "fubar")
	filedata := "LeBron Raymone James Sr. is an American professional basketball player for the Los Angeles Lakers of the National Basketball Association. He is often regarded as the greatest basketball player of all time, which has resulted in frequent comparisons to Michael Jordan"
	BronClone1.StoreFile("test", []byte(filedata))
	file, err := BronClone2.LoadFile("test")
	if string(file) != filedata { //String(file) is NULL. I.e. our filedata is NULL.
		t.Error("LoadFile failed", err)
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

//Test a simple revoke scenario.
func TestRevoke(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "foobar")
	//cain, _ := InitUser("cain", "X")
	// Alice creates + stores file "test"		
	filename := "test"
	data := []byte("I love Kevin Moy")
	alice.StoreFile(filename, data)
	// Alice shares the file with Bob
	bobtoken, err := alice.ShareFile(filename, "bob")
	bob.ReceiveFile(filename, "alice", bobtoken)

	// Revoke that mf
	err = alice.RevokeFile(filename, "bob")
	if err != nil {
		t.Error("RevokeFile Failed.", err)
	}
	// Check that alice still has access to file
	_, err = alice.LoadFile(filename)
	if err != nil {
		t.Error("", err)
	}
	// But bob does not
	_, e := bob.LoadFile(filename)
	if e == nil {
		t.Error("RevokeFile did not revoke access to other users.", err)
	}
}
//Test Simple Single-User File Appending.
func TestAppend(t *testing.T){
    u, _ := GetUser("alice", "fubar")
    f := []byte("Franchise Tag on Me Bron Bron")
    u.StoreFile("fileB", f)
    u.AppendFile("fileB", []byte("Steph"))
    u.AppendFile("fileB", []byte("Curry"))

    f1 := append(f, []byte("Steph")...)
    f1 = append(f1, []byte("Curry")...)
    f2, err2 := u.LoadFile("fileB")
    if err2 != nil {
        t.Error("Could Not Load File", err2)
    }
    if !reflect.DeepEqual(f1, f2) {
        t.Error("Loaded Files Not Equal", f1, f2)
    }
}

// func TestTree(t *testing.T) {
// 	userlib.SetDebugStatus(true)

// 	tre := &Tree{"A", []*Tree{&Tree{"B", nil}, &Tree{"C", nil}}} // [A, [B,C]]
// 	t1 := tre.search("C")
// 	if !t1 {
// 		t.Error("Could Not Find Tree Node.")
// 	}
// 	t2 := tre.search("D")
// 	if t2 {
// 		t.Error("Found Nonexistent Tree Node.")
// 	}
// 	print(os.Stdout, tre)
// 	tre.addChild("C", "D")
// 	userlib.DebugMsg("-----")
// 	print(os.Stdout, tre)
// 	t2 = tre.search("D")
// 	if !t2 {
// 		t.Error("D should now be there. ")
// 	}
// 	//Test branchoff.
// 	tre.removeBranch("C")
// 	userlib.DebugMsg("-----")
// 	print(os.Stdout, tre)
// 	z := tre.search("C")
// 	if z {
// 		t.Error("C should be deleted. ")
// 	}
// 	z = tre.search("D")
// 	if z {
// 		t.Error("D should be deleted. ")
// 	}
// }

//Test that token authentication is maintained. 
func TestSenderVerify(t *testing.T) {
	u, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("bob", "foobar")
	u3, _ := InitUser("eve", "fooo")
	filedata := "No one has ever had as much hype as Lebron James has had to live up to, and he has delivered on every last drop."
	file := []byte(filedata)
	u.StoreFile("fi", file)
	//Share File with Eve (malicious)
	evetoken, err := u.ShareFile("fi", "eve")
	if err != nil {
		t.Error("Failed to share file.", err)
		return
	}
	err = u3.ReceiveFile("fi", "alice", evetoken)
	if err != nil {
		t.Error("Eve Did Not Receive File.", err)
		return
	}
	//Share file with Bob, now.
	bobtoken, err := u3.ShareFile("fi", "bob")
	if err != nil {
		t.Error("Failed to share file.", err)
		return
	}
	//Attempt transaction with invalid source. 
	err = u2.ReceiveFile("file2", "alice", bobtoken)
	if err == nil {
		t.Error("Eve sent this file, not alice. Verification error.", err)
		return
	}
	//Make the right transaction.
	err = u2.ReceiveFile("file2", "eve", bobtoken)
		if err != nil {
		t.Error("Failed to share file", err)
		return
	}
}

//Test that Bob can edit his shared file. 
func TestShare3(t *testing.T) {	
	u, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("bob", "foobar")
    fileA := []byte("I Don't Really Care if You Cry")
    u.StoreFile("fileA", fileA)
    //Share file with Bob
	alicetoken, err:= u.ShareFile("fileA", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}
	//Bob Receives File.
	err = u2.ReceiveFile("fileA", "alice", alicetoken)
	if err != nil {
		t.Error("Bob didn't receive", err)
		return
	}
	//Bob Edits file with whatever he wants. 
    u2.AppendFile("fileA", []byte("On The Real"))
    u2.AppendFile("fileA", []byte("You Shoulda Never Lied"))
    //Appended File for comparison.
    fileAB := append(fileA, []byte("On The Real")...)
    fileAB = append(fileAB, []byte("You Shoulda Never Lied")...)
    //Alice loads file.
    v2, err2 := u.LoadFile("fileA")
    if err2 != nil {
        t.Error("Failed to load File A", err2)
    }
    if !reflect.DeepEqual(fileAB, v2) {
        t.Error("Loaded File Not Equal", fileAB, v2)
    }

}

//Test a deep revoke scenario, where A shares to B, who shares to C.
//A revokes B, which should also revoke C's access. 
func TestDeepRevoke(t *testing.T) {
	clear()
	alice, _ := InitUser("alice", "fubar")
	bob, _ := InitUser("bob", "foobar")
	cain, _ := InitUser("cain", "X")
	kevin, _ := InitUser("kevin", "Lebron")
	// Alice creates + stores file "test"		
	filename := "test"
	data := []byte("I love Kevin Moy")
	alice.StoreFile(filename, data)
	// Alice shares the file with Bob
	alicetoken, err := alice.ShareFile(filename, "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}
	_ = bob.ReceiveFile(filename, "alice", alicetoken)
	//Bob shares with Cain and Kevin
	bobtoken, err := bob.ShareFile(filename, "cain")
	_ = cain.ReceiveFile(filename, "bob", bobtoken)
	bobtoken, err = bob.ShareFile(filename, "kevin")
	_ = kevin.ReceiveFile(filename, "bob", bobtoken)
	//Check that Cain and Kevin can edit file. 
	_ = cain.AppendFile("test", []byte("-SIGNED BY CAIN"))
    edited1 := append(data, []byte("-SIGNED BY CAIN")...)
    f, err2 := bob.LoadFile("test")
    if err2 != nil {
        t.Error("Failed to load File", err2)
    }
    if !reflect.DeepEqual(edited1, f) {
        t.Error("Loaded File Not Equal", edited1, f)
    }
   	_ = kevin.AppendFile("test", []byte("AND KEVIN"))
    edited2 := append(edited1, []byte("AND KEVIN")...)
    f, _ = alice.LoadFile("test")
	if !reflect.DeepEqual(edited2, f) {
        t.Error("Loaded File Not Equal", edited1, f)
    }
    //Alice revokes Bob. Cain and Kevin no longer have access.
    _ = alice.RevokeFile("test", "bob")
    f, err2 = bob.LoadFile("test")
    if err2 == nil {
        t.Error("Bob shouldn't be able to load file", err2)
    }
    f, err2 = cain.LoadFile("test")
    if err2 == nil {
        t.Error("Cain shouldn't be able to load file", err2)
    }
    f, err2 = kevin.LoadFile("test")
    if err2 == nil {
        t.Error("Kevin shouldn't be able to load file", err2)
    }
    err2 = cain.AppendFile("test", []byte("Fuck You Alice"))
    if err2 == nil {
    	t.Error("Cain shouldn't be able to append file", err2)
    }
    err2 = kevin.AppendFile("test", []byte("Fuck You Alice"))
    if err2 == nil {
    	t.Error("Cain shouldn't be able to append file", err2)
    }
    f, _ = alice.LoadFile("test")
	if !reflect.DeepEqual(edited2, f) {
        t.Error("Loaded File Not Equal", edited1, f)
    }
}

func TestDenialOfService(t *testing.T) {
	clear()
	dwight, err1 := InitUser("dwight", "schrute")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}
	jim, err2 := InitUser("jim", "halpert")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	v := []byte("My Middle Name is Kurt. NOT FART")
	dwight.StoreFile("file1", v)
	v1 := []byte("I'LL DESTROY HALPERT!")
	dwight.StoreFile("file2", v1)

	// Dwight shares his file with Jim
	dwightToken, err := dwight.ShareFile("file1", "jim")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	receivedError := jim.ReceiveFile("file1", "dwight", dwightToken)
	if receivedError != nil {
		t.Error("Could not share file in DoS test", receivedError)
		return
	}

	data, e := jim.LoadFile("file1")

	var stolenKey []byte
	datastore := userlib.DatastoreGetMap()
	for k := range datastore { //loop to steal the dwight's key for file1
		dwightToken, _ := userlib.DatastoreGet(k)
		if string(dwightToken) == string(data) {
			stolenKey = dwightToken
		}
	}

	//Dwight revoked permission from Jim
	revokeError := dwight.RevokeFile("file1", "jim")
	if revokeError != nil {
		t.Error("RevokeFile Failed.", revokeError)
	}

	receivedError = jim.ReceiveFile("file1", "dwight", string(stolenKey))
	if receivedError == nil {
		t.Error("Should've failed!", receivedError)
		return
	}

	data, e = jim.LoadFile("file1")
	if e == nil {
		t.Error("Jim should not have permission even after stealing the key!.", err)
	}

	// userlib.DatastoreSet()

}

//Tests that a user whose permission was revoked can have permission if owner reshares file
func TestReshareFile(t *testing.T) {
	dwight, err1 := InitUser("dwight", "schrute")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}
	jim, err2 := InitUser("jim", "halpert")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	v := []byte("My Middle Name is Kurt. NOT FART")
	dwight.StoreFile("file1", v)

	// Dwight shares his file with Jim
	dwightToken, err := dwight.ShareFile("file1", "jim")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}
	receivedError := jim.ReceiveFile("file1", "dwight", dwightToken)
	if receivedError != nil {
		t.Error("Jim failed to receive file from Dwight in TestReshareFile")
		return
	}

	//Dwight revoked permission from Jim
	revokeError := dwight.RevokeFile("file1", "jim")
	if revokeError != nil {
		t.Error("RevokeFile Failed.", revokeError)
	}

	// Jim does not have permission for now
	_, e := jim.LoadFile("file1")
	if e == nil {
		t.Error("RevokeFile did not revoke access to other users.", err)
	}

	// Dwight forgives and shares his file with Jim once more
	dwightToken, err = dwight.ShareFile("file1", "jim")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}

	// Jim does have permission once more
	_, e = jim.LoadFile("file1")
	if e != nil {
		t.Error("Jim should have permission again!", e)
	}

}

func TestUntouchedUser(t *testing.T) {
	clear()
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	datastore := userlib.DatastoreGetMap()
	for k, _ := range datastore {
		userlib.DatastoreSet(k, []byte("lebron james sux!"))
	}

	_, contaminated := GetUser("alice", "fubar")
	if contaminated == nil {
		t.Error("Alice was contaminated by Datastore! Should've errored!", contaminated)
		return
	}

}
