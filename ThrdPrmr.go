package main

import  "errors"
import  "fmt"
import  "github.com/tidwall/gjson"
import  "os"
import  "os/exec"
import  "regexp"
import  "slices"
import  "strings"
import  "time"

func    main () {
	/***1***/
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
			`ERRR: Config file invalid. [%s]` /****/, _bb10.Error (),
		)
		Log (_cb05)
		os.Exit (1)
	}
	Log ("STTS: Running...")
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
	_bg05 :=int   (gjson.Get(_bb50, "Domains.#").Int ())
	_bg10 :=[ ] string {}
	for _cb05 := 1; _cb05 <= _bg05; _cb05 ++ {
		/***1***/
		_cc01 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.Id",_cb05-1),
		).String ( )
		_cc02 := gjson.Get (
			_bb50, fmt.Sprintf ("Domains.%d.PrmryDomain", _cb05-1),
		).String ( )
		_cc03 := [ ]string {}
		if regexp.MustCompile (
		`^[a-z0-9]{8,8}\-[a-z0-9]{4,4}\-[a-z0-9]{4,4}\-[a-z0-9]{4,4}\-[a-z0-9]{12,12}$`,
		).MatchString (_cc01) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Domain ID %s invalid.`/***/  , _cc01,
			)
			Log (_db05)
			os.Exit (1)
		}
		if slices.Contains  (_bg10, _cc01) {
			_db05 := fmt.Sprintf (
				`ERRR: Domain ID %s in use twice.`  , _cc01,
			)
			Log (_db05)
			os.Exit (1)
		}
		_bg10 =append (_bg10,_cc01)
		if regexp.MustCompile (
		`^[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*)+$`,
		).MatchString (_cc02) == false {
			_db05 := fmt.Sprintf (
				`ERRR: Primary domain %s invalid.`  , _cc02,
			)
			Log (_db05)
			os.Exit (1)
		}
		_cc03 =append (_cc03, strings.ToLower (_cc02))
		/***2***/
		_cd05 := gjson.Get  (
			_bb50, fmt.Sprintf(
				"Domains.%d.ScndryDomain.#",_cb05-1,
			),
		).Int ( )
		_cd10 := int  (_cd05)
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
				Log (_eb05)
				os.Exit (1)
			}
			_dc05 = strings.ToLower(_dc05)
			if slices.Contains (_cc03, _dc05) == false {
				_cc03 = append (_cc03, _dc05)
			}
		}
		/***3***/
		for _ , _db10 :=range _cc03 {
			_dc05 , _dc10 := exec.Command (
				"dig" , "@1.1.1.1", _db10, "A", "+short",
			).CombinedOutput ()
			if _dc10 !=  nil {
				_eb05 := fmt.Sprintf (
					`ERRR: Domain IP confirmation failed. [%s]`,
					_dc10.Error (),
				)
				Log (_eb05)
				os.Exit (1)
			}
			_dc50 := strings.Trim(string (_dc05), "\n ")
			if _dc50 !=  _bf50 {
				_eb05 := fmt.Sprintf (
					`ERRR: Domain %s pointing to IP %s not %s.`,
					 _db10,_dc50 , _bf50,
				)
				Log (_eb05)
				os.Exit (1)
			}
		}
		/***4***/
		//
	}
return
}
func    Log (log string) (error) {
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
		`%s [OpLog]: %s`, time.Now ().Format ("06-01-02/15:04:05"), log,
	)
	_, _bc10 :=_bb05.WriteString (_bb50 + "\n" )
	if _bc10 !=  nil {
		_cb05 := fmt.Sprintf (`Log recording failed. [%s]`   , _bc10.Error ())
		return errors.New (_cb05)
	}
	fmt.Println (_bb50)
	return  nil
}
