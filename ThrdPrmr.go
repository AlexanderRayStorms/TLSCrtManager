package main

import  "crypto/x509"
import  "encoding/pem"
import  "errors"
import  "fmt"
import  "github.com/tidwall/gjson"
import  "io/ioutil"
import  "os"
import  "os/exec"
import  "regexp"
import  "slices"
import  "strings"
import  "syscall"
import  "time"

func    main () {
	Log ("STTS: Running...")
	/***1***/
	Log ("STTS: Validating configuration...")
	_bb05 , _bb10 := os.ReadFile ("/etc/TLSCrtManager/Cnf")
	if _bb10 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: Config file loading failed. [%s]`, _bb10.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	_bb50 :=  string (_bb05)
	if gjson.Valid (_bb50) == false {
		_cb05 := fmt.Sprintf (
			`ERRR: Config file invalid.`,
		)
		Log (_cb05)
		os.Exit (1)
	}
	/***2***/
	_bc05 := gjson.Get (_bb50, "LetsEncrypAcntEmail").String ()
	if regexp.MustCompile (
	`^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*@[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$`,
	).MatchString (_bc05) == false {
		_cb05 := fmt.Sprintf (
			`ERRR: LetsEncrypt account email not present in configuration file ` +
			`or is invalid.` ,
		)
		Log (_cb05)
		os.Exit (1)
	}
	/***3***/
	Log ("STTS: Fetching this host's IP address...")
	_bf05 , _bf10 := exec.Command("curl","ident.me","-s").CombinedOutput ()
	if _bf10 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: LetsEncrypt account creation failed. [%s]`, _bf10.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	_bf50 :=string(_bf05)
	/***4***/
	Log ("STTS: Terminating defunct HTTP server...")
	_bf61 , _bf62 := exec.Command (
		"/bin/TLSCrtManager.Extnsn/ThrdPrmr-Extnsn00",
	).CombinedOutput ()
	if _bf62 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: Defunct HTTP servers termination failed. [%s:%s]`,
			_bf62.Error (), string (_bf61),
		)
		Log (_cb05)
		os.Exit (1)
	}
	/***4***/
	Log ("STTS: Starting HTTP server to use for LetsEncrypt domain verification...")
	_bf76 :=exec.Command(
		"sws","-a","0.0.0.0","-p", "1081", "-d", "/var/tmp/TLSCrtManager", "-g", "trace",
	)
	_bf81 , _bf82 :=_bf76.StdoutPipe ( )
	_bf83 , _bf84 :=_bf76.StderrPipe ( )
	if _bf82 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: HTTP server std-out fetch failed. [%s]`, _bf82.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	if _bf84 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: HTTP server std-err fetch failed. [%s]`, _bf84.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	_bf91 :=_bf76.Start ()
	if _bf91 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: HTTP server setup failed (1). [%s]`, _bf91.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	time.Sleep  (time.Second * 2 )
	_bf92 := exec.Command ("ps", "-a")
	_bf94 , _bf95 := _bf92.CombinedOutput ()
	if _bf95 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: HTTP server setup confirmation failed (1). [%s]`,
			 _bf95.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	if regexp.MustCompile (
		fmt.Sprintf (`(?m)%d.+sws$`, _bf76.Process.Pid),
	).MatchString (string (_bf94))==false {
		_ca01  := make([]byte, 1048576)
		_ca02  := make([]byte, 1048576)
		_ca11 , _ := _bf81.Read (_ca01)
		_ca12 , _ := _bf83.Read (_ca02)
		_ca21 := string(_ca01 [:_ca11])
		_ca22 := string(_ca02 [:_ca12])
		_cb05 := fmt.Sprintf (
			"ERRR: HTTP server setup failed (2).\n%s\n%s\n%s]",
			"Server crashed", string (_ca21) , string (_ca22) ,
		)
		Log (_cb05)
		os.Exit (1)
	}
	defer func( ) {
		_bf76.Process.Signal (syscall.SIGTERM)
		_bf76.Process.Signal (syscall.SIGKILL)
	} ( )	
	/***5***/
	Log ("STTS: Processing domains...")
	_bg05 :=int   (gjson.Get(_bb50, "Domains.#").Int ( ))
	_bg10 :=[ ] string {}
	for _cb05 := 1; _cb05 <= _bg05; _cb05 ++ {
		/***1***/
		_cb51 := fmt.Sprintf ("%d", _cb05)
		_cb52 := fmt.Sprintf ("%d", _bg05)
		for len(_cb51)<  len (  _cb52 )  { _cb51 = "0" + _cb51 }
		/***2***/
		_cc01 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.Id",_cb05-1),
		).String ( )
		_cc02 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.PrmryDomain", _cb05-1),
		).String ( )
		_cc03 := [ ]string {}
		_cc04 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.KeyExportPath" , _cb05-1),
		).String ( )
		_cc05 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.CrtExportPath" , _cb05-1),
		).String ( )
		/***3***/
		_cc01  = strings.ToLower (_cc01)
		if regexp.MustCompile (
		`^[a-z0-9]{8,8}\-[a-z0-9]{4,4}\-[a-z0-9]{4,4}\-[a-z0-9]{4,4}\-[a-z0-9]{12,12}$`,
		).MatchString (_cc01) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain ID %s invalid.`/***/  , _cc01,
			)
			Log(_db05);continue
		}
		if slices.Contains  (_bg10, _cc01) {
			_db05 := fmt.Sprintf (
				`ERRR: Domain ID %s in use twice.`  , _cc01,
			)
			Log(_db05);continue
		}
		_bg10 =append(_bg10, _cc01)
		Log (fmt.Sprintf (
			"STTS: Domain %s/%s [%s]: Picked up_",
			_cb51, _cb52, _cc01,
		))
		Log (fmt.Sprintf (
			"STTS: Domain %s/%s [%s]: Parameters validation in progress...",
			_cb51, _cb52, _cc01,
		))
		if regexp.MustCompile (
		`^[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*)+$`,
		).MatchString(_cc02) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Primary domain %s invalid.`  , _cc02,
			)
			Log(_db05);continue
		}
		_cc03 =append (_cc03, strings.ToLower (_cc02))
		/***4***/
		_cd05 := gjson.Get  (
			_bb50, fmt.Sprintf(
				"Domains.%d.ScndryDomain.#",_cb05-1,
			),
		).Int ( )
		_cd10 := int  (_cd05)
		_QT01 := false
		for _db05:=1  ;_db05 <= _cd10; _db05++ {
			_dc05 := gjson.Get (
				_bb50, fmt.Sprintf(
					"Domains.%d.ScndryDomain.%d",_cb05-1,_db05-1,
				),
			).String()
			if regexp.MustCompile (
			`^[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*)+$`,
			).MatchString (_dc05) == false {
				_eb05 := fmt.Sprintf (
					`ERRR: Secondary domain %s invalid.`,_dc05  ,
				)
				_QT01 =true
				Log (_eb05) ; break
			}
			_dc05 = strings.ToLower(_dc05)
			if slices.Contains     (_cc03, _dc05) == false {
				_cc03 = append (_cc03, _dc05)
			}
		}
		if  _QT01 ==true { continue }
		/***5***/
		Log (fmt.Sprintf (
			"STTS: Domain %s/%s [%s]: Confirming all domains point to this host...",
			_cb51, _cb52, _cc01,
		))
		_QT02 := false
		for _ , _db10 :=range _cc03 {
			_dc05 , _dc10 := exec.Command (
				"dig" , "@1.1.1.1", _db10, "A", "+short",
			).CombinedOutput ()
			if _dc10 !=  nil {
				_eb05 := fmt.Sprintf (
					`ERRR: Domain IP confirmation failed. [%s]`,
					_dc10.Error (),
				)
				_QT02 =true
				Log (_eb05) ; break
			}
			_dc50 := strings.Trim(string (_dc05), "\n ")
			if _dc50 !=  _bf50 {
				_eb05 := fmt.Sprintf (
					`ERRR: Domain %s pointing to IP %s not %s.`,
					 _db10,_dc50 , _bf50,
				)
				_QT02 =true
				Log (_eb05) ; break
			}
		}
		if  _QT02 ==true { continue }
		/***6***/
		_cd24 := regexp.MustCompile (`\/[a-zA-Z0-9\-_\.]+$`).ReplaceAllString(_cc04,"")
		_cd25 := regexp.MustCompile (`\/[a-zA-Z0-9\-_\.]+$`).ReplaceAllString(_cc05,"")
		_, _cd35 := os.Stat (_cd24)
		_, _cd45 := os.Stat (_cd25)
		if _cd35 !=  nil && os.IsNotExist (_cd35) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s key export path existence check failed. [%s]`,
				_cc01, _cd35.Error (),
			)
			Log(_db05);continue
		}
		if _cd45 !=  nil && os.IsNotExist (_cd45) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s crt export path existence check failed. [%s]`,
				_cc01, _cd45.Error (),
			)
			Log(_db05);continue
		}
		if _cd35 !=  nil && os.IsNotExist (_cd35) {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s key export path does not exist.`, _cc01,
			)
			Log(_db05);continue
		}
		if _cd45 !=  nil && os.IsNotExist (_cd45) {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s crt export path does not exist.`, _cc01,
			)
			Log(_db05);continue
		}
		/***7***/
		_CB51 = _cb51; _CB52= _cb52; _CC01=_cc01
		Log (fmt.Sprintf (
			"STTS: Domain %s/%s [%s]: Processing begins...",
			_cb51, _cb52, _cc01,
		))
		_, _ce10 := os.Stat ("/etc/TLSCrtManager/Dmn/" + _cc01 + ".key")
		_, _cf10 := os.Stat ("/etc/TLSCrtManager/Dmn/" + _cc01 + ".crt")
		if _ce10 !=  nil && os.IsNotExist (_ce10) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s key existence check failed. [%s]`, _cc01,
				_ce10.Error (),
			)
			Log(_db05);continue
		}
		if _cf10 !=  nil && os.IsNotExist (_cf10) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s crt existence check failed. [%s]`, _cc01,
				_cf10.Error (),
			)
			Log(_db05);continue
		}
		if _ce10 !=  nil && os.IsNotExist (_ce10) {
			main_Phase2 (_cc01, _cc02, _cc03, _cc04, _cc05);continue
		}
		if _cf10 !=  nil && os.IsNotExist (_cf10) {
			main_Phase2 (_cc01, _cc02, _cc03, _cc04, _cc05);continue
		}
		_cg05 , _cg10 := ioutil.ReadFile ("/etc/TLSCrtManager/Dmn/" + _cc01 + ".crt")
		if _cg10 !=  nil {
			_db05 := fmt.Sprintf (
				`ERRR: Domain %s crt fetch failed. [%s]`, _cc01,
				_cg10.Error (),
			)
			Log(_db05);continue
		}
		_cg50 :=_cg05
		_ch05 := []*pem.Block {}
		for len(_cg50 )> 0  {
			_da51 := strings.Trim (string(_cg50), "\n ")
			_cg50  = []byte(_da51 )
			_db05 , _db10 := pem.Decode  (_cg50)
			if len (_db10)== len (_cg50) {break}
			_cg50 = _db10
			if _db05== nil {continue /**/}
			_ch05 = append (_ch05,_db05  )
		}
		var _ci05 *x509.Certificate = nil;
		for _db05, _db10 := range  _ch05 {
			_dc05 , _dc10 := x509.ParseCertificate (_db10.Bytes)
			if _dc10 !=  nil {
				_eb05 := fmt.Sprintf (
					`ERRR: Domain %s crt subsection %d decode failed. [%s]`,
					_cc01, _db05 + 1,_dc10.Error(),
				)
				Log(_eb05);break
			}
			_Slct := true
			for _ , _eb10 := range _cc03 {
				_dc05 := _dc05.VerifyHostname (_eb10 )
				if _dc05 != nil {
					 _Slct=false
					 break
				}
			}
			if _Slct == true {   _ci05= _dc05; break }
		}
		if _ci05 ==   nil  {
			main_Phase2(_cc01, _cc02, _cc03, _cc04, _cc05);continue
		}
		if time.Now ().Add (time.Hour * 1080).Unix ( )> _ci05.NotAfter.Unix () {
			main_Phase2(_cc01, _cc02, _cc03, _cc04, _cc05);continue
		}
		main_Phase3 (_cc01, _cc02, _cc03, _cc04, _cc05)
	}
return
}
func    main_Phase2 (
	Id  , PrmryDomain string, ScndryDomain []string, KeyExportPath, CrtExportPath string,
	)   {
	/***1***/
	Log (fmt.Sprintf (
		"STTS: Domain %s/%s [%s]: Requesting new TLS key & crt from LetsEncrypt %v....",
		_CB51, _CB52, _CC01 , ScndryDomain,
	))
	/***2***/
	_bb05 := ""
	for _ , _cb10 := range ScndryDomain {
		if _bb05 != "" { _bb05 = _bb05 + " " }
		_bb05  = fmt.Sprintf (`%s-w /var/tmp/TLSCrtManager -d %s` , _bb05, _cb10)
	}
	_bc05 , _bc10 := exec.Command (
		"/bin/TLSCrtManager.Extnsn/ThrdPrmr-Extnsn01",
		_bb05, Id, ScndryDomain [0] , 
	).CombinedOutput ()
	if _bc10 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: Domain %s/%s [%s]: Certificate fetch failed. [%s:%s]`,
			_CB51, _CB52, _CC01 , _bc10.Error (), string (_bc05),
		)
		Log(_cb05)
		return
	}
	main_Phase3 (Id, PrmryDomain, ScndryDomain, KeyExportPath, CrtExportPath)
}
func    main_Phase3 (
	Id  , PrmryDomain string, ScndryDomain []string, KeyExportPath, CrtExportPath string,
	)   {
	/***1***/
	Log (fmt.Sprintf (
		"STTS: Domain %s/%s [%s]: Exporting TLS key & crt....",
		_CB51, _CB52, _CC01 , 
	))
	/***2***/
	_bc05 , _bc10 := exec.Command (
		"/bin/TLSCrtManager.Extnsn/ThrdPrmr-Extnsn02",
		Id, KeyExportPath, CrtExportPath,
	).CombinedOutput ()
	if _bc10 !=  nil {
		_cb05 := fmt.Sprintf (
			`ERRR: Domain %s/%s [%s]: Certificate export failed. [%s:%s]`,
			_CB51, _CB52, _CC01 , _bc10.Error (), string (_bc05),
		)
		Log(_cb05)
		return
	}
}
func    Log (log string ) (error) {
	_bb05 , _bb10 := os.OpenFile (
		"/etc/TLSCrtManager/Log",
		os.O_APPEND|os.O_WRONLY|os.O_CREATE,
		0600,
	)
	if _bb10 !=  nil {
		_cb05 := fmt.Sprintf (`Log file opening failed. [%s]`, _bb10.Error ())
		return errors.New (_cb05)
	}
	defer _bb05.Close()
	_bb50 := fmt.Sprintf (
		`%s [OpLog]:%s`, time.Now ().Format ("2006-01-02/15:04:05"), log,
	)
	_, _bc10 :=_bb05.WriteString (_bb50 + "\n" )
	if _bc10 !=  nil {
		_cb05 := fmt.Sprintf (`Log recording failed. [%s]`   , _bc10.Error ())
		return errors.New (_cb05)
	}
	fmt.Println (_bb50)
	return  nil
}
var     (
	_CB51 string
	_CB52 string
	_CC01 string
)
