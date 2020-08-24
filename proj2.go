package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
    // You neet to add with
    // go get github.com/cs161-staff/userlib
    "github.com/cs161-staff/userlib"

    // Life is much easier with json:  You are
    // going to want to use this so you can easily
    // turn complex structures into strings etc...
    "encoding/json"

    // Likewise useful for debugging, etc...
    "encoding/hex"

    // UUIDs are generated right based on the cryptographic PRNG
    // so lets make life easier and use those too...
    //
    // You need to add with "go get github.com/google/uuid"
    "github.com/google/uuid"

    // Useful for debug messages, or string manipulation for datastore keys.
    "strings"

    // Want to import errors.
    "errors"

    // Optional. You can remove the "_" there, but please do not touch
    // anything else within the import bracket.
    _ "strconv"
    //DELETE THESE DELETE THESE DELETE THESE
    // "io"
    // "fmt"
    // "os"
    // "reflect"
    // if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
    // see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
    // Creates a random UUID
    f := uuid.New()
    userlib.DebugMsg("UUID as string:%v", f.String())

    // Example of writing over a byte of f
    f[0] = 10
    userlib.DebugMsg("UUID as string:%v", f.String())

    // takes a sequence of bytes and renders as hex
    h := hex.EncodeToString([]byte("fubar"))
    userlib.DebugMsg("The hex: %v", h)

    // Marshals data into a JSON representation
    // Will actually work with go structures as well
    d, _ := json.Marshal(f)
    userlib.DebugMsg("The json data: %v", string(d))
    var g uuid.UUID
    json.Unmarshal(d, &g)
    userlib.DebugMsg("Unmashaled data %v", g.String())

    // This creates an error type
    userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

    // And a random RSA key.  In this case, ignoring the error
    // return value
    var pk userlib.PKEEncKey
    var sk userlib.PKEDecKey
    pk, sk, _ = userlib.PKEKeyGen()
    userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
    for x := range ret {
        ret[x] = data[x]
    }
    return
}

// Helper function: Check if error and handle via panic func if there is.
func err_cheque(e error) {
    if e != nil {
        panic(e)
    }
}

//Helper function: LOGIN into Datastore and retrieve userdata object in byte form. 
func login(username string, password string) (b []byte, ok bool) {
    key := userlib.Argon2Key([]byte(password), []byte(username), 16)
    dsKey := bytesToUUID(key)
    b, ok = userlib.DatastoreGet(dsKey)
    return
}

//Helper function: Check if USERDATA can access FILE
func isAccessible(userdata *User, file File) bool {
    // ow := file.Collaborators
    // canAccess := false
    // fileUsers := strings.Split(ow, ",") //List of the file users (includes file owner)
    // if file.Owner == userdata.Username{
    //     canAccess = true
    //     return canAccess
    // }
    // for i:=0;i<len(fileUsers);i++{
    //     if fileUsers[i] == userdata.Username{
    //         canAccess = true
    //     }
    // }
    // return canAccess
    // userlib.DebugMsg("IN ISACCESSIBLE.\n",)
    // userlib.DebugMsg("USERNAME: %s\n", userdata.Username)
	return file.ShareTree.search(userdata.Username)
}
// Helper function: separate signed decrypted data into signature and data. 
func separate(signed []byte) (UD []byte, sig []byte) {
    UD = signed[:len(signed)-64]
    sig = signed[len(signed)-64:]
    return UD, sig
}
		
// Helper function: concatenate (FOR HMAC) 
func concatenate(b1 []byte, b2 []byte) Pair {
    return Pair{b1, b2}
}

//Helper function: Generate 2 random 16 bit (symmetric) encryption + signing keys.
func EncMACKeyGen() (K_Enc []byte, K_Sign []byte){
    K1 := userlib.RandomBytes(16)
    K2 := userlib.RandomBytes(16)
    return K1, K2
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
    DPK []byte //Private key for decryption (RSA). Type userlib.PKEDECKey
    SignSK []byte //Private key for signing (RSA). Type userlib.DSSignKey
    SharedFiles map[string]File //Map of filenames to file objects SHARED WITH this user. 
    CreatedFiles map[string]File //map of filenames to created file objects (by this user)
    SharedUsers map[string]map[string]bool //map of (user's) files to a SET of usernames. 
}

// The structure definition for file metadata. 
type File struct{
	ID uuid.UUID //Uniqueness tag. Key for filedata in datastore.  
	Owner string
	K_Sign []byte //KEY for signing (Owner's use)
	K_Enc []byte //KEY for decryption. (Owner's Use)
	//Potential Fields that might also be useful..
	Collaborators string //Comma-delimited string that includes owner and collaborators on file.
	ShareTree *Tree
}

// The structure definition for a pair. We can use this to represent signed and encrypted data.
type Pair struct{
	B1 []byte
	B2 []byte
}
//Sharing tree struct for a single file. Root should always be owner. 
type Tree struct {
    Val string
    Children []*Tree
}

//https://golangcode.com/check-if-element-exists-in-slice/
// Find takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
func Find(slice []bool, val bool) (int, bool) {
    for i, item := range slice {
        if item == val {
            return i, true
        }
    }
    return -1, false
}

//Return if NAME exists in share tree T.
func (t *Tree) search(name string) bool {
	if t == nil {
		return false
	}
    if t.Val == name {
        return true
    }
	var trees_fd []bool
	for _, child := range t.Children {
	    trees_fd = append(trees_fd, child.search(name))
	}
	_, found := Find(trees_fd, true)
	return found
}

//Return a pointer to node (DFS).
func findNode(t *Tree, name string) *Tree {
    if t.Val == name {
        return t
    }else {
    	empty := &Tree{}
    	potentialNode := &Tree{} //Empty tree pointer. 
    	for _, child := range t.Children {
    		potentialNode = findNode(child, name)
    		if !NodeEquals(potentialNode, empty) {
    			// userlib.DebugMsg("FOUND: %s", potentialNode.val)
    			break
    		}
    	}
    	return potentialNode
    }
    return nil
}
//Return if tree nodes are equal by value. 
func NodeEquals(t1 *Tree, t2 *Tree) bool {
	return t1.Val == t2.Val
}
//Add a child to a leaf node in the tree
func (t *Tree) addChild(leaf string, child string) {
	if t == nil {
		return 
	}
	t = findNode(t, leaf)
	childNode := &Tree{child, nil}
	t.Children = append(t.Children, childNode)
}

//Remove branch off tree (revoke a user lol)
func remove(s []*Tree, i int) []*Tree {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

//IMPLEMENT
func (t *Tree) removeBranch(target string) {
	for i, child := range t.Children {
		if child.Val == target {
			t.Children = remove(t.Children, i)
			return
		}
	}
}

// func print(w io.Writer, t *Tree) {
//     if t == nil {
//         return
//     }
//     fmt.Fprintf(w, "%s ", t.Val)
//     for _, child := range t.Children {
//     	print(w, child)
//     }
// }

// Store User object securely into datastore (sign and encrypt).
// We assume our User object is populated. ID will be purely username-based. 
func StoreUser(ud *User) error {
    //The datastore key will be formed primarily from our secure password. 
    //This is because this pw is unique per user. 
    key := userlib.Argon2Key([]byte(ud.Password),[]byte(ud.Username),32)
    // user_datastore_key := key[32:48]
	UDB, _ := json.Marshal(ud) //Userdata in bytes
	K_SIGN := key[:16]
	K_ENC := key[16:]
	//Encrypt userdata.
	enc_user := userlib.SymEnc(K_ENC, userlib.RandomBytes(16), UDB)
	//Sign encrypted userdata. 
	sig, _ := userlib.HMACEval(K_SIGN, enc_user)
	secure_user := Pair{enc_user, sig}

	//SET USER DATASTORE KEY AS HASH ON USERNAME. 
	uID, _ := userlib.HMACEval(K_SIGN, []byte(ud.Username))
	user_ID := bytesToUUID(uID)

	SUB, _ := json.Marshal(secure_user) //secure user in byte form, for storage. 
	userlib.DatastoreSet(user_ID, SUB)
	return nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing 
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//Return a secure 128 byte chunk which forms the basis of our keys.  
	//First, generate all necessary keys. Store public keys in keystore.
	K_ENC, K_DEC, _ := userlib.PKEKeyGen()
	K_SIGN, K_VERIFY, _ := userlib.DSKeyGen()

	keyExists, ok := userlib.KeystoreGet(username + "ENCRYPT", K_ENC)
	if keyExists != nil {
		return nil, errors.New("Uername already exists.")
	}

	userlib.KeystoreSet(username + "ENCRYPT", K_ENC)
	userlib.KeystoreSet(username + "VERIFY", K_VERIFY)	

	//Next, encrypt our private keys into the datastore. 
	//Create 2 keys from Argon2Key, that serves as a SECURE key since it is based off login info.

	//Finally, populate userdata struct and return pointer. 
	userdata.Username = username
	userdata.Password = password
	userdata.DPK, _ = json.Marshal(K_DEC)
	userdata.SignSK, _ = json.Marshal(K_SIGN)
	userdata.CreatedFiles = make(map[string]File)
	userdata.SharedUsers = make(map[string]map[string]bool)
	//Finally, secure userdata obj in datastore.
	StoreUser(userdataptr)
	if err != nil {
		return nil, err
	}
	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
    key := userlib.Argon2Key([]byte(password),[]byte(username), 32)
	K_SIGN := key[:16]
	K_ENC := key[16:]
	//Reform key to store userdata. This key will only be correct with correct user + PW.
	uID, _ := userlib.HMACEval(K_SIGN, []byte(username))
	user_ID := bytesToUUID(uID)
	// Fetch user from datastore at provided path. Userdata Encrypted and Signed, and marshaled.
	UD_ES, ok := userlib.DatastoreGet(user_ID)
	// Check if Username/PW valid (if corresponding userdata exists)
	if !ok {
		return nil, errors.New("Invalid Login.")
	}
	var pair Pair
	err = json.Unmarshal(UD_ES, &pair)
	if err != nil {return nil, errors.New("Unmarshal Error.")}
	//Split ciphertext -> UD, HMAC
	ENC_UD := pair.B1
	SIG := pair.B2
	//Now, integrity/auth check by recalculating MAC. 
	recalc_MAC, _ := userlib.HMACEval(K_SIGN, ENC_UD)
	if !userlib.HMACEqual(SIG, recalc_MAC) {
		return nil, errors.New("File Corrupted.")
	}
	//Pass login! Now, decrypt userdata object and return pointer. 
	var userdata User
	userdataptr = &userdata
	ud := userlib.SymDec(K_ENC, ENC_UD)
	_ = json.Unmarshal(ud, userdataptr)
	return userdataptr, nil
}
//Helper function to encrypt and sign a file given metadata (keys)
func EncryptAndSign(file File, data []byte, filename string) []byte{
	IV := userlib.RandomBytes(16)
	data_enc := userlib.SymEnc(file.K_Enc, IV, data)
	sig, _ := userlib.HMACEval(file.K_Sign, data_enc)
	secure_filedata := append(data_enc, sig...)
	return secure_filedata
}


// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
    //This function is two-pronged: First, we must store metadata properly in User, 
    //then securely store (file) data in the datastore. 
	var file File
	username := userdata.Username
	pw := userdata.Password
	//Generate a key unique to a user and his filename.
	key := userlib.Argon2Key([]byte(username), []byte(filename + pw), 16)
	file_ID, _ := uuid.FromBytes(key)
	//Test if file already exists. CANNOT overwrite (?)
	testFile ,_ := userlib.DatastoreGet(file_ID)
	if testFile != nil {
		return
	}
	//Populate Metadata. 
	K_ENC, K_SIGN := EncMACKeyGen()
	file.Collaborators = username
	file.Owner = username
	file.ID = uuid.New()
	file.K_Sign = K_SIGN
	file.K_Enc = K_ENC
	file.ShareTree = &Tree{username, nil}
	// printFileMeta(&file)
	MetaBytes, _ := json.Marshal(file)
	var temp File
	json.Unmarshal(MetaBytes, &temp)
	metaID := uuid.New()
	userlib.DatastoreSet(metaID, MetaBytes)
	
	//We'll store our meta ID next. 
	d, _ := json.Marshal(metaID)
	userlib.DatastoreSet(file_ID, d)

	//Next, we need to store filedata. 
	data_ID := uuid.New()
	//Encrypt and Sign File Data. 
	secure_FD := EncryptAndSign(file,data,filename)
	userlib.DatastoreSet(data_ID, secure_FD)
	//Similarly, store filedata ID. 
	dID, _ := json.Marshal(data_ID)
	userlib.DatastoreSet(file.ID, dID)

	userdata.CreatedFiles[filename] = file
	return
}

// Check file permissions on username.
func CheckPermissions(file File, username string) bool {
	collabs := strings.Split(file.Collaborators, ",")
    for _, name := range collabs {
    	if name == username {
    		return true
    	}
    }
    return false
}

// Check file permissions on shareTree.
func CheckPermissionsTree(file File, username string) bool {
	return file.ShareTree.search(username)
}

//Helper function that returns pointer to file meta.
func getFileMeta(userdata *User, filename string) *File {
	username := userdata.Username
	pw := userdata.Password
	key := userlib.Argon2Key([]byte(username), []byte(filename + pw), 16)
	file_ID, _ := uuid.FromBytes(key)
	metaIDB, _ := userlib.DatastoreGet(file_ID)
	var metaID uuid.UUID
	json.Unmarshal(metaIDB, &metaID)
	fileB, ok := userlib.DatastoreGet(metaID)
	//File Does Not Exist in Datastore. 
	if fileB == nil || !ok {
		return nil
	}
	var file File
	json.Unmarshal(fileB, &file)
	return &file
}

func getMetaID(userdata *User, filename string) uuid.UUID {
	username := userdata.Username
	pw := userdata.Password
	key := userlib.Argon2Key([]byte(username), []byte(filename + pw), 16)
	file_ID, _ := uuid.FromBytes(key)
	metaIDB, _ := userlib.DatastoreGet(file_ID)
	var metaID uuid.UUID
	json.Unmarshal(metaIDB, &metaID)
	return metaID
}
// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//First, get file meta.
	file := getFileMeta(userdata, filename)
	if file == nil {
		return errors.New("File Does Not Exist!")
	}
	//Check if User can access filename. 
	canAccess := isAccessible(userdata, *file)
	if !canAccess {
		return errors.New("File Access Denied")
	}
	//Checks passed. Append to filedata.
	//First, MARK original file to indicate an edit (append) is made. 
	new_filedata_ID := uuid.New()
	//KEY: EACH OF THESE MARKS IS FIT INTO A 38 BYTE CHUNK!
	mark, _ := json.Marshal(new_filedata_ID)
	original, _ := userlib.DatastoreGet(file.ID)
	// KEY: 
	original = append(original, mark...)
	userlib.DatastoreSet(file.ID, original)
	//Now, encrypt and sign NEW data. Note we aren't actually overwriting the original!
	secure_appended := EncryptAndSign(*file, data, filename)
	userlib.DatastoreSet(new_filedata_ID, secure_appended)
	return
}

func printFileMeta(file *File) {
	userlib.DebugMsg("ID: %s\n", file.ID)
	userlib.DebugMsg("Owner: %s\n", file.Owner)
	userlib.DebugMsg("MAC KEY: %08b\n", file.K_Sign)
	userlib.DebugMsg("ENC KEY: %08b\n", file.K_Enc)
	userlib.DebugMsg("Share Tree: ")
	// print(os.Stdout, file.ShareTree)
}

// This loads a file from the Datastore.
// 
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	file := getFileMeta(userdata, filename)
	// printFileMeta(file)
	if file == nil {
		return nil, errors.New("File Does Not Exist!")
	}
	access := isAccessible(userdata, *file)
	if access == false {
		return nil, errors.New("File Access Denied.")
	}
	//Acquire data UUID
	appendIDs, _ := userlib.DatastoreGet(file.ID) //Get file ID.
	var filedata []byte //Return this.

	//We'll apply a chunks process, each chunk being 38 bytes. 
	//Each chunk corresponds to a particular append.
	//Our process is that we RE-APPEND everything: our original filedata and all the appends. 		
	ID_SIZE := 38
	numAppends := len(appendIDs)/ID_SIZE
	for i:=0;i<numAppends;i++{
		var appendID []byte 
		if i == numAppends-1 {
			appendID = appendIDs[ID_SIZE*i:]
		} else {
			appendID = appendIDs[ID_SIZE*i:ID_SIZE*(i+1)]
		}
		//Get the ID of our encrypted data append. 
		var id uuid.UUID
		err = json.Unmarshal(appendID, &id)
		//Get encrypted filedata. 		
		filedata_ES, _ := userlib.DatastoreGet(id) 
		if filedata_ES == nil {
			return nil, errors.New("File does not exist!")
		}
		//Verify.
		enc_data, sig := separate(filedata_ES)
		calc_MAC, _ := userlib.HMACEval(file.K_Sign, enc_data)
		if !userlib.HMACEqual(calc_MAC, sig) {
			return nil, errors.New("Corrupted File Data!")
		}
		//Decrypt data chunk
		data_chunk := userlib.SymDec(file.K_Enc, enc_data)
		filedata = append(filedata, data_chunk...)
	}
	
	return filedata, nil	
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	username := userdata.Username
	pw := userdata.Password
	key := userlib.Argon2Key([]byte(username), []byte(filename + pw), 16)
	file := getFileMeta(userdata, filename)
	if file == nil {
		return "", errors.New("File Does Not Exist!")
	}
	canAccess := isAccessible(userdata, *file)
	if canAccess == false {
		return
	}
	_ , ok := userlib.KeystoreGet(recipient + "ENCRYPT")
	if !ok {
		return
	}
	//Add recipient to userdata's sharedUsers map. 
	// userdata.SharedUsers[filename] = append(userdata.SharedUsers[filename], recipient)

	//Add him as a leaf node in our file's sharetree.
	file.ShareTree.addChild(username, recipient)
	//Re-store file metadata, (under the same ID as before)
	//Marshal file meta.
	newFile, _ := json.Marshal(file)
	//(Asymmetric) Encrypt and Sign (?). NAH.
	metaID := getMetaID(userdata, filename)
	userlib.DatastoreSet(metaID, newFile)
	//Now, create share token from our uniquely generated key. 
	var K_SIGN userlib.DSSignKey
	json.Unmarshal(userdata.SignSK, &K_SIGN)
	sig, _ := userlib.DSSign(K_SIGN,key)
	magic_str := append(key, sig...)
	return string(magic_str), err
}

func token_separate(token []byte) ([]byte, []byte) {
	if len(token) < 32 {
		return nil, nil
	}
	return token[:16], token[16:]
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	username := userdata.Username
	pw := userdata.Password
	//Convert magic string back to byte form. Edge case: Token length < 32???
	token := []byte(magic_string)
	//VERIFY that magic_string is from sender. 
	K_VERIFY, _ := userlib.KeystoreGet(sender + "VERIFY")
	sender_key, sig := token_separate(token)
	err1 := userlib.DSVerify(K_VERIFY,sender_key,sig)
	if err1 != nil {
		return errors.New("Digital Signature Failure! Token tampered with.")
	}
	//Recreate our file ID from our sender key.
	fileidKey, _ := uuid.FromBytes(sender_key)
	recipient_key, _ := userlib.DatastoreGet(fileidKey)
	var a uuid.UUID
	json.Unmarshal(recipient_key, &a)
	//Get our filedata, in bytes. 
	fileB, _ := userlib.DatastoreGet(a)
	if fileB == nil {
		return errors.New("File Doesn't Exist!")
	}
	//Now, create our OWN key from our user+pw+filename, and make our own file ID from this.
	key := userlib.Argon2Key([]byte(username), []byte(filename + pw), 16)
	recipient_keyID, err := uuid.FromBytes(key)

	test, _ := userlib.DatastoreGet(recipient_keyID)
	//File already exists for user. 
	if test != nil {
		return errors.New("File Already Exists!")
	}
	userlib.DatastoreSet(recipient_keyID, recipient_key)
	return err
}

//Return true if TARGET_USERNAME exists in sharetree on a particular file. 
func revokedUserExistsTree(file *File, target_username string) (bool) {
	return file.ShareTree.search(target_username)	
}

//Remove by value (TARGET) from string byte slice, and return slice with removed target. 
//Honestly this should be a built in method but fuck it this language sucks anyway
func removeUser(slice []string, target string) []string {
	for i:=0;i<len(slice);i++{
		if slice[i] == target {
			newSlice := append(slice[:i], slice[i+1:]...)
			return newSlice
		}
	}
	return slice
}
// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	file := getFileMeta(userdata, filename)
	metaID := getMetaID(userdata, filename)
	if file == nil {
		return errors.New("File Doesn't Exist!")
	}
	if file.Owner != userdata.Username{
		return errors.New("Only the owner may revoke access.")
	}
	//First, check if revoked user exists. 
	exists := revokedUserExistsTree(file, target_username)
	if !exists {
		return errors.New("Target user is not a collaborator! Nothing to revoke.")
	}
	//Update the collaborators (without revoked user + his children)
	file.ShareTree.removeBranch(target_username)
	fileB, _ := json.Marshal(file)
	userlib.DatastoreDelete(metaID)
	userlib.DatastoreSet(metaID, fileB)

	return nil
}