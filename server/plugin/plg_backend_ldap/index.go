package plg_backend_ldap

/*
 * Introduction
 * ============
 * To get a sample of what this backend can do:
 * - example.com: http://127.0.0.1:8334/login#type=ldap&hostname=ldap://ldap.forumsys.com&bind_cn=uid%3Dtesla,dc%3Dexample,dc%3Dcom&bind_password=password&base_dn=dc%3Dexample,dc%3Dcom
 * - freeipa:     http://127.0.0.1:8334/login#type=ldap&hostname=ldap://ipa.demo1.freeipa.org&bind_cn=uid%3Dadmin,cn%3Dusers,cn%3Daccounts,dc%3Ddemo1,dc%3Dfreeipa,dc%3Dorg&bind_password=Secret123&base_dn=dc%3Ddemo1,dc%3Dfreeipa,dc%3Dorg
 */

import (
	"encoding/json"
	"fmt"
	. "github.com/mickael-kerjean/filestash/server/common"
	"gopkg.in/ldap.v3"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var LDAPCache AppCache

func init() {
	Backend.Register("ldap", LDAP{})
	LDAPCache = NewAppCache(2, 1)
	LDAPCache.OnEvict(func(key string, value interface{}) {
		c := value.(*LDAP)
		c.dial.Close()
	})
}

type LDAP struct {
	dial   *ldap.Conn
	baseDN string
}

func (l LDAP) Init(params map[string]string, app *App) (IBackend, error) {
	if obj := LDAPCache.Get(params); obj != nil {
		return obj.(*LDAP), nil
	}

	dialURL := func() string {
		if params["port"] == "" {
			// default port will be set by the LDAP library
			return params["hostname"]
		}
		return fmt.Sprintf("%s:%s", params["hostname"], params["port"])
	}()

	d, err := ldap.DialURL(dialURL)
	if err != nil {
		return nil, err
	}
	if err = d.Bind(params["bind_cn"], params["bind_password"]); err != nil {
		return nil, err
	}

	b := &LDAP{baseDN: params["base_dn"], dial: l}
	LDAPCache.Set(params, b)
	return b, nil
}

func (l LDAP) LoginForm() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name:  "type",
				Type:  "hidden",
				Value: "ldap",
			},
			{
				Name:        "hostname",
				Type:        "text",
				Placeholder: "Hostname",
			},
			{
				Name:        "bind_cn",
				Type:        "text",
				Placeholder: "bind CN",
			},
			{
				Name:        "bind_password",
				Type:        "password",
				Placeholder: "Bind CN password",
			},
			{
				Name:        "base_dn",
				Type:        "text",
				Placeholder: "Base DN",
			},
			{
				Name:        "advanced",
				Type:        "enable",
				Placeholder: "Advanced",
				Target:      []string{"ldap_path", "ldap_port"},
			},
			{
				Id:          "ldap_path",
				Name:        "path",
				Type:        "text",
				Placeholder: "Path",
			},
			{
				Id:          "ldap_port",
				Name:        "port",
				Type:        "number",
				Placeholder: "Port",
			},
		},
	}
}

func (l LDAP) Ls(path string) ([]os.FileInfo, error) {
	baseDN := l.pathToBase(path)
	files := make([]os.FileInfo, 0)

	// explore the current folder
	sr, err := l.dial.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	))
	if err != nil {
		return files, err
	}

	for i := 0; i < len(sr.Entries); i++ {
		entry := sr.Entries[i]

		// filename as will appear in the UI:
		filename := strings.TrimSuffix(entry.DN, ","+baseDN)

		// data type as will appear in the UI
		t := "file"
		if len(entry.Attributes) != 1 {
			continue
		}
		objectClasses := entry.Attributes[0].Values
		for j := 0; j < len(objectClasses); j++ {
			if s := Schema[objectClasses[j]]; s != nil {
				if s.IsContainer {
					t = "directory"
					break
				}
			}
		}

		if t == "file" {
			filename += ".form"
		}

		files = append(files, File{
			FName: filename,
			FType: t,
			FTime: 1497276000000,
			FSize: -1,
		})
	}
	return files, nil
}

func (l LDAP) Cat(path string) (io.ReadCloser, error) {
	///////////////////////////////////////////////
	// STEP1: search for the requested entry
	baseDN := l.pathToBase(path)
	sr, err := l.dial.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 2, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	))
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) != 1 {
		return nil, ErrNotValid
	}
	entry := sr.Entries[0]

	///////////////////////////////////////////////
	// STEP2: create the form that fits in the entry schema
	var forms = []FormElement{
		NewFormElementFromAttributeWithValue("dn", baseDN),
		NewFormElementFromAttributeWithValue("objectClass", strings.Join(entry.GetAttributeValues("objectClass"), ", ")),
	}
	forms[0].ReadOnly = true
	forms[0].Required = true

	required := make([]FormElement, 0)
	optional := make([]FormElement, 0)
	for _, value := range entry.GetAttributeValues("objectClass") {
		required = append(required, FindRequiredAttributesForObject(value)...)
		optional = append(optional, FindOptionalAttributesForObject(value)...)
	}
	sort.SliceStable(required, sortFormElement(required))
	sort.SliceStable(optional, sortFormElement(optional))
	forms = append(forms, required...)
	forms = append(forms, optional...)

	///////////////////////////////////////////////
	// STEP3: fillup the form with the entry values

	for i := 0; i < len(entry.Attributes); i++ {
		data := struct {
			key   string
			value string
		}{
			key:   entry.Attributes[i].Name,
			value: strings.Join(entry.Attributes[i].Values, ", "),
		}

		var i int
		for i = range forms {
			if forms[i].Name == data.key {
				forms[i].Value = data.value
			}
		}

		if i == len(forms) {
			forms = append(forms, NewFormElementFromAttributeWithValue(data.key, data.value))
		}

		if forms[i].Name == "gidNumber" {
			for _, value := range entry.GetAttributeValues("objectClass") {
				if value == "posixAccount" {
					forms[i].Datalist = l.autocompleteLDAP("(objectclass=posixGroup)", "gidNumber")
					break
				}
			}
		} else if forms[i].Name == "memberUid" {
			for _, value := range entry.GetAttributeValues("objectClass") {
				if value == "posixGroup" {
					forms[i].Datalist = l.autocompleteLDAP("(objectclass=posixAccount)", "cn")
					forms[i].MultiValue = true
					break
				}
			}
		}
	}

	///////////////////////////////////////////////
	// STEP4: Send the form data over
	b, err := Form{Elmnts: forms}.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return NewReadCloserFromBytes(b), nil
}

func (l LDAP) Mkdir(path string) error {
	ldapNode := strings.Split(filepath.Base(path), "=")
	if len(ldapNode) != 2 {
		return ErrNotValid
	}

	var objectClass string
	switch ldapNode[0] {
	case "ou":
		objectClass = "organizationalUnit"
	case "o":
		objectClass = "organization"
	case "c":
		objectClass = "country"
	default:
		return ErrNotValid
	}

	forms := FindRequiredAttributesForObject(objectClass)
	for i := range forms {
		if forms[i].Name == "objectClass" {
			forms[i].Value = strings.Join(FindDerivatedClasses(objectClass), ", ")
		} else {
			forms[i].Value = ldapNode[1]
		}
	}

	if err := l.dial.Add(&ldap.AddRequest{
		DN: l.pathToBase(path),
		Attributes: func() []ldap.Attribute {
			attributes := make([]ldap.Attribute, 0, len(forms))
			for i := 0; i < len(forms); i++ {
				attributes = append(attributes, ldap.Attribute{
					Type: forms[i].Name,
					Vals: strings.Split(fmt.Sprintf("%s", forms[i].Value), ", "),
				})
			}
			return attributes
		}(),
	}); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func (l LDAP) Rm(path string) error {
	var err error

	sr, err := l.dial.Search(ldap.NewSearchRequest(
		l.pathToBase(path),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	))
	if err != nil {
		return err
	}

	for i := len(sr.Entries) - 1; i >= 0; i-- {
		if err == nil {
			err = l.dial.Del(&ldap.DelRequest{
				DN: sr.Entries[i].DN,
			})
		}
	}
	return err
}

func (l LDAP) Mv(from string, to string) error {
	toBase := l.pathToBase(to)
	fromBase := l.pathToBase(from)

	return l.dial.ModifyDN(&ldap.ModifyDNRequest{
		DN: fromBase,
		NewRDN: func(t string) string {
			a := strings.Split(t, ",")
			if len(a) == 0 {
				return t
			}
			return a[0]
		}(toBase),
		DeleteOldRDN: true,
		NewSuperior: func(t string) string {
			a := strings.Split(t, ",")
			if len(a) == 0 {
				return t
			}
			return strings.Join(a[1:], ",")
		}(toBase),
	})
}

func (l LDAP) Touch(path string) error {
	ldapNode := strings.Split(filepath.Base(path), "=")
	if len(ldapNode) != 2 {
		return ErrNotValid
	}
	var objectClass []string
	switch ldapNode[0] {
	case "cn":
		objectClass = []string{"inetOrgPerson", "posixAccount"}
	default:
		return ErrNotValid
	}
	ldapNode[1] = strings.TrimSuffix(ldapNode[1], ".form")

	var uniqueForms = make(map[string]FormElement)
	for i := 0; i < len(objectClass); i++ {
		for _, obj := range FindRequiredAttributesForObject(objectClass[i]) {
			uniqueForms[obj.Name] = obj
		}
	}
	var forms = make([]FormElement, 0)
	for _, element := range uniqueForms {
		if element.Name == "objectClass" {
			element.Value = strings.Join(objectClass, ", ")
		} else {
			element.Value = l.generateLDAP(element.Name, ldapNode[1])
		}
		forms = append(forms, element)
	}

	if err := l.dial.Add(&ldap.AddRequest{
		DN: l.pathToBase(path),
		Attributes: func() []ldap.Attribute {
			attributes := make([]ldap.Attribute, 0, len(forms))
			for i := 0; i < len(forms); i++ {
				attributes = append(attributes, ldap.Attribute{
					Type: forms[i].Name,
					Vals: strings.Split(fmt.Sprintf("%s", forms[i].Value), ", "),
				})
			}
			return attributes
		}(),
	}); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func (l LDAP) Save(path string, file io.Reader) error {
	var data map[string]FormElement
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return err
	} else if data["dn"].Value == nil {
		return ErrNotValid
	}
	if l.pathToBase(path) != data["dn"].Value { // change in the path can only be perform via `MV`
		return ErrNotAllowed
	}

	sr, err := l.dial.Search(ldap.NewSearchRequest(
		fmt.Sprintf("%s", data["dn"].Value),
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{},
		nil,
	))
	if err != nil {
		return err
	}
	if len(sr.Entries) != 1 {
		return ErrNotValid
	}

	var attributes = make(map[string]*[]string)
	for i := 0; i < len(sr.Entries[0].Attributes); i++ {
		attributes[sr.Entries[0].Attributes[i].Name] = &sr.Entries[0].Attributes[i].Values
	}
	modifyRequest := ldap.NewModifyRequest(fmt.Sprintf("%s", data["dn"].Value), nil)
	for key := range data {
		if data[key].Value == nil || key == "dn" {
			continue
		}
		if attributes[key] == nil {
			modifyRequest.Add(key, strings.Split(fmt.Sprintf("%s", data[key].Value), ", "))
		} else if data[key].Value != strings.Join(*attributes[key], ", ") {
			modifyRequest.Replace(key, strings.Split(fmt.Sprintf("%s", data[key].Value), ", "))
		}
	}
	for key := range attributes {
		if data[key].Value == nil && attributes[key] != nil {
			modifyRequest.Delete(key, *attributes[key])
		}
	}

	if err := l.dial.Modify(modifyRequest); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func (l LDAP) Meta(path string) Metadata {
	return Metadata{
		CanUpload:       NewBool(false),
		HideExtension:   NewBool(true),
		RefreshOnCreate: NewBool(true),
	}
}

func (l LDAP) pathToBase(path string) string {
	path = strings.TrimSuffix(path, ".form")
	if path = strings.Trim(path, "/"); path == "" {
		return l.baseDN
	}
	pathArray := strings.Split(path, "/")
	baseArray := strings.Split(l.baseDN, ",")
	reversedPath := []string{}
	for i := len(pathArray) - 1; i >= 0; i-- {
		reversedPath = append(reversedPath, pathArray[i])
	}
	return strings.Join(append(reversedPath, baseArray...), ",")
}

func (l LDAP) autocompleteLDAP(filter string, value string) []string {
	val := []string{}
	sr, err := l.dial.Search(ldap.NewSearchRequest(
		l.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{value},
		nil,
	))
	if err != nil {
		return val
	}
	for i := 0; i < len(sr.Entries); i++ {
		val = append(val, sr.Entries[i].GetAttributeValue(value))
	}
	sort.Strings(val)
	return val
}

func (l LDAP) generateLDAP(name string, deflts string) string {
	d := strings.Split(deflts, "-")
	switch name {
	case "cn":
		return strings.ToLower(deflts)
	case "uid":
		return strings.ToLower(deflts)
	case "uidNumber":
		return "65534"
	case "homeDirectory":
		return "/home/" + strings.ToLower(deflts)
	case "loginShell":
		return "/bin/false"
	case "aliasedObjectName":
		return strings.ToLower(deflts)
	case "c":
		return strings.ToLower(deflts)
	case "o":
		return strings.ToLower(deflts)
	case "userPassword":
		return "welcome"
	case "gidNumber":
		return "65534"
	case "sn":
		if len(d) == 2 {
			return strings.Title(d[1])
		}
		return strings.Title(strings.Join(d, " "))
	case "givenName":
		if len(d) == 2 {
			return strings.Title(d[0])
		}
		return strings.Title(strings.Join(d, " "))
	default:
		return deflts
	}
}

type LDAPSchema struct {
	IsContainer bool     // can be used as a folder to store more entry?
	Description string   // doc string coming from the schema
	Type        string   // AUXILIARY / STRUCTURAL or ABSTRACT
	Silent      bool     // show up (or not) as part of the client autocomplete
	Required    []string // required attributes
	Optional    []string // optional attributes
	Inherit     []string // class this schema inherits
}

func FindRequiredAttributesForObject(objectClass string) []FormElement {
	if Schema[objectClass] == nil {
		return make([]FormElement, 0)
	}
	elements := make([]FormElement, 0, len(Schema[objectClass].Required))
	for i := 0; i < len(Schema[objectClass].Inherit); i++ {
		els := FindRequiredAttributesForObject(Schema[objectClass].Inherit[i])
		elements = append(elements, els...)
	}
	for i := 0; i < len(Schema[objectClass].Required); i++ {
		elements = append(
			elements,
			func() FormElement {
				f := NewFormElementFromAttribute(Schema[objectClass].Required[i])
				f.Required = true
				return f
			}(),
		)
	}
	return elements
}

func FindOptionalAttributesForObject(objectClass string) []FormElement {
	if Schema[objectClass] == nil {
		return make([]FormElement, 0)
	}
	elements := make([]FormElement, 0, len(Schema[objectClass].Optional))
	for i := 0; i < len(Schema[objectClass].Inherit); i++ {
		els := FindOptionalAttributesForObject(Schema[objectClass].Inherit[i])
		elements = append(elements, els...)
	}
	for i := 0; i < len(Schema[objectClass].Optional); i++ {
		elements = append(
			elements,
			NewFormElementFromAttribute(Schema[objectClass].Optional[i]),
		)
	}
	return elements
}

func NewFormElementFromAttribute(attr string) FormElement {
	var form = FormElement{}
	if LDAPAttribute[attr] != nil {
		form = *LDAPAttribute[attr]
	}
	if form.Name == "" {
		form.Name = attr
	}
	if form.Type == "" {
		form.Type = "text"
	}
	return form
}

func NewFormElementFromAttributeWithValue(attr string, value string) FormElement {
	f := NewFormElementFromAttribute(attr)
	f.Value = value
	return f
}

func FindDerivatedClasses(objectClass string) []string {
	classes := []string{objectClass}
	if Schema[objectClass] == nil {
		return classes
	}
	for i := 0; i < len(Schema[objectClass].Inherit); i++ {
		classes = append(classes, FindDerivatedClasses(Schema[objectClass].Inherit[i])...)
	}
	return classes
}

func sortFormElement(e []FormElement) func(i, j int) bool {
	return func(i, j int) bool {
		l := LDAPAttribute[e[i].Name]
		r := LDAPAttribute[e[j].Name]

		if l == nil && r == nil { // tie
			return false
		} else if r == nil {
			return true
		} else if l == nil {
			return false
		}

		if l.Order == 0 && r.Order == 0 {
			return false
		} else if l.Order == 0 {
			return false
		} else if r.Order == 0 {
			return true
		}
		return l.Order < r.Order
	}
}

/*
 * The following is loading LDAP schema that was found on the openLDAP directory:
 * https://github.com/openldap/openldap/tree/master/servers/slapd/schema
 * As such, the source code in OpenLDAP says:
 * "Redistribution and use in source and binary forms, with or without modification,
 * are permitted only as authorized by the OpenLDAP Public License."
 * This license can be found: http://www.openldap.org/software/release/license.html
 *
 * It includes: core.schema, inetorgperson.schema, collective.schema, corba.schema, cosine.schema
 * duaconf.schema, dyngroup.schema, java.schema, misc.schema, msuser.schema, nis.schema, openldap.schema
 * pmi.schema, ppolicy.schema.
 */
var Schema = map[string]*LDAPSchema{
	// SCHEMA: core.schema
	"top": {
		Description: "Top of the superclass chain - RFC2256",
		Type:        "ABSTRACT",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{},
		Required:    []string{"objectClass"},
		Optional:    []string{},
	},
	"alias": {
		Description: "An alias - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"aliasedObjectName"},
		Optional:    []string{},
	},
	"country": {
		Description: "A country - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: true,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"c"},
		Optional:    []string{"searchGuide", "description"},
	},
	"locality": {
		Description: "A locality - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"street", "seeAlso", "searchGuide", "st", "l", "description"},
	},
	"organization": {
		Description: "An organization - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: true,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"o"},
		Optional:    []string{"userPassword", "searchGuide", "seeAlso", "businessCategory", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "st", "l", "description"},
	},
	"organizationalUnit": {
		Description: "An organizational unit - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: true,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"ou"},
		Optional:    []string{"userPassword", "searchGuide", "seeAlso", "businessCategory", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "st", "l", "description"},
	},
	"person": {
		Description: "A person - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"sn", "cn"},
		Optional:    []string{"userPassword", "telephoneNumber", "seeAlso", "description"},
	},
	"organizationalPerson": {
		Description: "An organizational person - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"person"},
		Required:    []string{},
		Optional:    []string{"title", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "ou", "st", "l"},
	},
	"organizationalRole": {
		Description: "An organizational role - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "seeAlso", "roleOccupant", "preferredDeliveryMethod", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "ou", "st", "l", "description"},
	},
	"groupOfNames": {
		Description: "A group of names (DNs) - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"member", "cn"},
		Optional:    []string{"businessCategory", "seeAlso", "owner", "ou", "o", "description"},
	},
	"residentialPerson": {
		Description: "An residential person - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"person"},
		Required:    []string{"l"},
		Optional:    []string{"businessCategory", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "preferredDeliveryMethod", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "st", "l"},
	},
	"applicationProcess": {
		Description: "An application process - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"seeAlso", "ou", "l", "description"},
	},
	"applicationEntity": {
		Description: "An application entity - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"presentationAddress", "cn"},
		Optional:    []string{"supportedApplicationContext", "seeAlso", "ou", "o", "l", "description"},
	},
	"dSA": {
		Description: "A directory system agent (a server) - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"applicationEntity STRUCTURAL"},
		Required:    []string{},
		Optional:    []string{"knowledgeInformation"},
	},
	"device": {
		Description: "A device - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"serialNumber", "seeAlso", "owner", "ou", "o", "l", "description"},
	},
	"strongAuthenticationUser": {
		Description: "A strong authentication user - RFC2256",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"userCertificate"},
		Optional:    []string{},
	},
	"certificationAuthority": {
		Description: "A certificate authority - RFC2256",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"authorityRevocationList", "certificateRevocationList", ""},
		Optional:    []string{"crossCertificatePair"},
	},
	"groupOfUniqueNames": {
		Description: "A group of unique names (DN and Unique Identifier) - RFC2256",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"uniqueMember", "cn"},
		Optional:    []string{"businessCategory", "seeAlso", "owner", "ou", "o", "description"},
	},
	"userSecurityInformation": {
		Description: "A user security information - RFC2256",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"supportedAlgorithms"},
	},
	"certificationAuthority-V2": {
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"certificationAuthority"},
		Required:    []string{},
		Optional:    []string{"deltaRevocationList"},
	},
	"cRLDistributionPoint": {
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"certificateRevocationList", "authorityRevocationList", "deltaRevocationList"},
	},
	"dmd": {
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"dmdName"},
		Optional:    []string{"userPassword", "searchGuide", "seeAlso", "businessCategory", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "st", "l", "description"},
	},
	"pkiUser": {
		Description: "A PKI user - RFC2587",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"userCertificate"},
	},
	"pkiCA": {
		Description: "PKI certificate authority - RFC2587",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"authorityRevocationList", "certificateRevocationList", "cACertificate", "crossCertificatePair"},
	},
	"deltaCRL": {
		Description: "PKI user - RFC2587",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"deltaRevocationList"},
	},
	"labeledURIObject": {
		Description: "Object that contains the URI attribute type - RFC2079",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"labeledURI"},
	},
	"simpleSecurityObject": {
		Description: "Simple security object - RFC1274",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"userPassword"},
		Optional:    []string{},
	},
	"dcObject": {
		Description: "Domain component object - RFC2247",
		Type:        "AUXILIARY",
		IsContainer: true,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"dc"},
		Optional:    []string{},
	},
	"uidObject": {
		Description: "Uid object - RFC2377",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"uid"},
		Optional:    []string{},
	},
	// SCHEMA: inetorgperson.schema
	"inetOrgPerson": {
		Description: "Internet Organizational Person - RFC2798",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"organizationalPerson"},
		Required:    []string{},
		Optional:    []string{"audio", "businessCategory", "carLicense", "departmentNumber", "displayName", "employeeNumber", "employeeType", "givenName", "homePhone", "homePostalAddress", "initials", "jpegPhoto", "labeledURI", "mail", "manager", "mobile", "o", "pager", "photo", "roomNumber", "secretary", "uid", "userCertificate", "x500uniqueIdentifier", "preferredLanguage", "userSMIMECertificate", "userPKCS12"},
	},
	// SCHEMA: collective.schema
	// SCHEMA: corba.schema
	"corbaContainer": {
		Description: "Container for a CORBA object",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{},
	},
	"corbaObject": {
		Description: "CORBA object representation",
		Type:        "ABSTRACT",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"corbaRepositoryId", "description"},
	},
	"corbaObjectReference": {
		Description: "CORBA interoperable object reference",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"corbaObject"},
		Required:    []string{"corbaIor"},
		Optional:    []string{},
	},
	// SCHEMA: cosine.schema
	"pilotObject": {
		Description: "Pilot object - RFC1274",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"info", "photo", "manager", "uniqueIdentifier", "lastModifiedTime", "lastModifiedBy", "dITRedirect", "audio"},
	},
	"pilotPerson": {
		Description: "The PilotPerson object class is used as a sub-class of person, to allow the use of a number of additional attributes to be assigned to entries of object class person",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"person"},
		Required:    []string{},
		Optional:    []string{"userid", "textEncodedORAddress", "rfc822Mailbox", "favouriteDrink", "roomNumber", "userClass", "homeTelephoneNumber", "homePostalAddress", "secretary", "personalTitle", "preferredDeliveryMethod", "businessCategory", "janetMailbox", "otherMailbox", "mobileTelephoneNumber", "pagerTelephoneNumber", "organizationalStatus", "mailPreferenceOption", "personalSignature"},
	},
	"newPilotPerson": {
		Description: "The PilotPerson object class is used as a sub-class of person, to allow the use of a number of additional attributes to be assigned to entries of object class person",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"person"},
		Required:    []string{},
		Optional:    []string{"userid", "textEncodedORAddress", "rfc822Mailbox", "favouriteDrink", "roomNumber", "userClass", "homeTelephoneNumber", "homePostalAddress", "secretary", "personalTitle", "preferredDeliveryMethod", "businessCategory", "janetMailbox", "otherMailbox", "mobileTelephoneNumber", "pagerTelephoneNumber", "organizationalStatus", "mailPreferenceOption", "personalSignature"},
	},
	"account": {
		Description: "The Account object class is used to define entries representing computer accounts.  The userid attribute should be used for naming entries of this object class.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"userid"},
		Optional:    []string{"description", "seeAlso", "localityName", "organizationName", "organizationalUnitName", "host"},
	},
	"document": {
		Description: "The Document object class is used to define entries which represent documents.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"documentIdentifier"},
		Optional:    []string{"commonName", "description", "seeAlso", "localityName", "organizationName", "organizationalUnitName", "documentTitle", "documentVersion", "documentAuthor", "documentLocation", "documentPublisher"},
	},
	"room": {
		Description: "The Room object class is used to define entries representing rooms. The commonName attribute should be used for naming pentries of this object class.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"commonName"},
		Optional:    []string{"roomNumber", "description", "seeAlso", "telephoneNumber"},
	},
	"documentSeries": {
		Description: "The Document Series object class is used to define an entry which represents a series of documents (e.g., The Request For Comments papers).",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"commonName"},
		Optional:    []string{"description", "seeAlso", "telephonenumber", "localityName", "organizationName", "organizationalUnitName"},
	},
	"domain": {
		Description: "The Domain object class is used to define entries which represent DNS or NRS domains.  The domainComponent attribute should be used for naming entries of this object class.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"domainComponent"},
		Optional:    []string{"associatedName", "organizationName", "description", "businessCategory", "seeAlso", "searchGuide", "userPassword", "localityName", "stateOrProvinceName", "streetAddress", "physicalDeliveryOfficeName", "postalAddress", "postalCode", "postOfficeBox", "streetAddress", "facsimileTelephoneNumber", "internationalISDNNumber", "telephoneNumber", "teletexTerminalIdentifier", "telexNumber", "preferredDeliveryMethod", "destinationIndicator", "registeredAddress", "x121Address"},
	},
	"RFC822localPart": {
		Description: "The RFC822 Local Part object class is used to define entries which represent the local part of RFC822 mail addresses.  This treats this part of an RFC822 address as a domain.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"domain"},
		Required:    []string{},
		Optional:    []string{"commonName", "surname", "description", "seeAlso", "telephoneNumber", "physicalDeliveryOfficeName", "postalAddress", "postalCode", "postOfficeBox", "streetAddress", "facsimileTelephoneNumber", "internationalISDNNumber", "telephoneNumber", "teletexTerminalIdentifier", "telexNumber", "preferredDeliveryMethod", "destinationIndicator", "registeredAddress", "x121Address"},
	},
	"dNSDomain": {
		Description: "The DNS Domain (Domain NameServer) object class is used to define entries for DNS domains.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"domain"},
		Required:    []string{},
		Optional:    []string{"ARecord", "MDRecord", "MXRecord", "NSRecord", "SOARecord", "CNAMERecord"},
	},
	"domainRelatedObject": {
		Description: "An object related to an domain - RFC1274. The Domain Related Object object class is used to define entries which represent DNS/NRS domains which are \"equivalent\" to an X.500 domain: e.g., an organisation or organisational unit",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"associatedDomain"},
		Optional:    []string{},
	},
	"friendlyCountry": {
		Description: "The Friendly Country object class is used to define country entries in the DIT.  The object class is used to allow friendlier naming of countries than that allowed by the object class country.  The naming attribute of object class country, countryName, has to be a 2 letter string defined in ISO 3166.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"country"},
		Required:    []string{"friendlyCountryName"},
		Optional:    []string{},
	},
	"pilotOrganization": {
		Description: "The PilotOrganization object class is used as a sub-class of organization and organizationalUnit to allow a number of additional attributes to be assigned to entries of object classes organization and organizationalUnit.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"organization", "organizationalUnit"},
		Required:    []string{},
		Optional:    []string{"buildingName"},
	},
	"pilotDSA": {
		Description: "The PilotDSA object class is used as a sub-class of the dsa object class to allow additional attributes to be assigned to entries for DSAs.",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"dsa"},
		Required:    []string{},
		Optional:    []string{"dSAQuality"},
	},
	"qualityLabelledData": {
		Description: "The Quality Labelled Data object class is used to allow the ssignment of the data quality attributes to subtrees in the DIT",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"dsaQuality"},
		Optional:    []string{"subtreeMinimumQuality", "subtreeMaximumQuality"},
	},
	// SCHEMA: duaconf.schema
	"DUAConfigProfile": {
		Description: "Abstraction of a base configuration for a DUA",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"defaultServerList", "preferredServerList", "defaultSearchBase", "defaultSearchScope", "searchTimeLimit", "bindTimeLimit", "credentialLevel", "authenticationMethod", "followReferrals", "dereferenceAliases", "serviceSearchDescriptor", "serviceCredentialLevel", "serviceAuthenticationMethod", "objectclassMap", "attributeMap", "profileTTL"},
	},
	// SCHEMA: dyngroup.schema
	"groupOfURLs": {
		Description: "undefined",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"memberURL", "businessCategory", "description", "o", "ou", "owner", "seeAlso"},
	},
	"dgIdentityAux": {
		Description: "undefined",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"dgIdentity", "dgAuthz"},
	},
	// SCHEMA: java.schema
	"javaContainer": {
		Description: "Container for a Java object",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{},
	},
	"javaObject": {
		Description: "Java object representation",
		Type:        "ABSTRACT",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"javaClassName"},
		Optional:    []string{"javaClassNames", "javaCodebase", "javaDoc", "description"},
	},
	"javaSerializedObject": {
		Description: "Java serialized object",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"javaObject"},
		Required:    []string{"javaSerializedData"},
		Optional:    []string{},
	},
	"javaMarshalledObject": {
		Description: "Java marshalled object",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"javaObject"},
		Required:    []string{"javaSerializedData"},
		Optional:    []string{},
	},
	"javaNamingReference": {
		Description: "JNDI reference",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"javaObject"},
		Required:    []string{},
		Optional:    []string{"javaReferenceAddress", "javaFactory"},
	},
	// SCHEMA: misc.schema
	"inetLocalMailRecipient": {
		Description: "Internet local mail recipient",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{},
	},
	"nisMailAlias": {
		Description: "NIS mail alias",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
	},
	// SCHEMA: msuser.schema
	"mstop": {
		Type:        "ABSTRACT",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"objectClass", "instanceType", "nTSecurityDescriptor", "objectCategory"},
		Optional:    []string{"cn", "description", "distinguishedName", "whenCreated", "whenChanged", "subRefs", "displayName", "uSNCreated", "isDeleted", "dSASignature", "objectVersion", "repsTo", "repsFrom", "memberOf", "ownerBL", "uSNChanged", "uSNLastObjRem", "showInAdvancedViewOnly", "adminDisplayName", "proxyAddresses", "adminDescription", "extensionName", "uSNDSALastObjRemoved", "displayNamePrintable", "directReports", "wWWHomePage", "USNIntersite", "name", "objectGUID", "replPropertyMetaData", "replUpToDateVector", "flags", "revision", "wbemPath", "fSMORoleOwner", "systemFlags", "siteObjectBL", "serverReferenceBL", "nonSecurityMemberBL", "queryPolicyBL", "wellKnownObjects", "isPrivilegeHolder", "partialAttributeSet", "managedObjects", "partialAttributeDeletionList", "url", "lastKnownParent", "bridgeheadServerListBL", "netbootSCPBL", "isCriticalSystemObject", "frsComputerReferenceBL", "fRSMemberReferenceBL", "uSNSource", "fromEntry", "allowedChildClasses", "allowedChildClassesEffective", "allowedAttributes", "allowedAttributesEffective", "possibleInferiors", "canonicalName", "proxiedObjectName", "sDRightsEffective", "dSCorePropagationData", "otherWellKnownObjects", "mS-DS-ConsistencyGuid", "mS-DS-ConsistencyChildCount", "masteredBy", "msCOM-PartitionSetLink", "msCOM-UserLink", "msDS-Approx-Immed-Subordinates", "msDS-NCReplCursors", "msDS-NCReplInboundNeighbors", "msDS-NCReplOutboundNeighbors", "msDS-ReplAttributeMetaData", "msDS-ReplValueMetaData", "msDS-NonMembersBL", "msDS-MembersForAzRoleBL", "msDS-OperationsForAzTaskBL", "msDS-TasksForAzTaskBL", "msDS-OperationsForAzRoleBL", "msDS-TasksForAzRoleBL", "msDs-masteredBy", "msDS-ObjectReferenceBL", "msDS-PrincipalName", "msDS-RevealedDSAs", "msDS-KrbTgtLinkBl", "msDS-IsFullReplicaFor", "msDS-IsDomainFor", "msDS-IsPartialReplicaFor", "msDS-AuthenticatedToAccountlist", "msDS-NC-RO-Replica-Locations-BL", "msDS-RevealedListBL", "msDS-PSOApplied", "msDS-NcType", "msDS-OIDToGroupLinkBl", "msDS-HostServiceAccountBL", "isRecycled", "msDS-LocalEffectiveDeletionTime", "msDS-LocalEffectiveRecycleTime", "msDS-LastKnownRDN", "msDS-EnabledFeatureBL", "msDS-ClaimSharesPossibleValuesWithBL", "msDS-MembersOfResourcePropertyListBL", "msDS-IsPrimaryComputerFor", "msDS-ValueTypeReferenceBL", "msDS-TDOIngressBL", "msDS-TDOEgressBL", "msDS-parentdistname", "msDS-ReplValueMetaDataExt", "msds-memberOfTransitive", "msds-memberTransitive", "msSFU30PosixMemberOf", "msDFSR-MemberReferenceBL", "msDFSR-ComputerReferenceBL"},
	},
	"group": {
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"mstop"},
		Required:    []string{"groupType"},
		Optional:    []string{"member", "nTGroupMembers", "operatorCount", "adminCount", "groupAttributes", "groupMembershipSAM", "controlAccessRights", "desktopProfile", "nonSecurityMember", "managedBy", "primaryGroupToken", "msDS-AzLDAPQuery", "msDS-NonMembers", "msDS-AzBizRule", "msDS-AzBizRuleLanguage", "msDS-AzLastImportedBizRulePath", "msDS-AzApplicationData", "msDS-AzObjectGuid", "msDS-AzGenericData", "msDS-PrimaryComputer", "mail", "msSFU30Name", "msSFU30NisDomain", "msSFU30PosixMember"},
	},
	"user": {
		Description: "undefined",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"mstop", "organizationalPerson"},
		Required:    []string{},
		Optional:    []string{"o", "businessCategory", "userCertificate", "givenName", "initials", "x500uniqueIdentifier", "displayName", "networkAddress", "employeeNumber", "employeeType", "homePostalAddress", "userAccountControl", "badPwdCount", "codePage", "homeDirectory", "homeDrive", "badPasswordTime", "lastLogoff", "lastLogon", "dBCSPwd", "localeID", "scriptPath", "logonHours", "logonWorkstation", "maxStorage", "userWorkstations", "unicodePwd", "otherLoginWorkstations", "ntPwdHistory", "pwdLastSet", "preferredOU", "primaryGroupID", "userParameters", "profilePath", "operatorCount", "adminCount", "accountExpires", "lmPwdHistory", "groupMembershipSAM", "logonCount", "controlAccessRights", "defaultClassStore", "groupsToIgnore", "groupPriority", "desktopProfile", "dynamicLDAPServer", "userPrincipalName", "lockoutTime", "userSharedFolder", "userSharedFolderOther", "servicePrincipalName", "aCSPolicyName", "terminalServer", "mSMQSignCertificates", "mSMQDigests", "mSMQDigestsMig", "mSMQSignCertificatesMig", "msNPAllowDialin", "msNPCallingStationID", "msNPSavedCallingStationID", "msRADIUSCallbackNumber", "msRADIUSFramedIPAddress", "msRADIUSFramedRoute", "msRADIUSServiceType", "msRASSavedCallbackNumber", "msRASSavedFramedIPAddress", "msRASSavedFramedRoute", "mS-DS-CreatorSID", "msCOM-UserPartitionSetLink", "msDS-Cached-Membership", "msDS-Cached-Membership-Time-Stamp", "msDS-Site-Affinity", "msDS-User-Account-Control-Computed", "lastLogonTimestamp", "msIIS-FTPRoot", "msIIS-FTPDir", "msDRM-IdentityCertificate", "msDS-SourceObjectDN", "msPKIRoamingTimeStamp", "msPKIDPAPIMasterKeys", "msPKIAccountCredentials", "msRADIUS-FramedInterfaceId", "msRADIUS-SavedFramedInterfaceId", "msRADIUS-FramedIpv6Prefix", "msRADIUS-SavedFramedIpv6Prefix", "msRADIUS-FramedIpv6Route", "msRADIUS-SavedFramedIpv6Route", "msDS-SecondaryKrbTgtNumber", "msDS-AuthenticatedAtDC", "msDS-SupportedEncryptionTypes", "msDS-LastSuccessfulInteractiveLogonTime", "msDS-LastFailedInteractiveLogonTime", "msDS-FailedInteractiveLogonCount", "msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon", "msTSProfilePath", "msTSHomeDirectory", "msTSHomeDrive", "msTSAllowLogon", "msTSRemoteControl", "msTSMaxDisconnectionTime", "msTSMaxConnectionTime", "msTSMaxIdleTime", "msTSReconnectionAction", "msTSBrokenConnectionAction", "msTSConnectClientDrives", "msTSConnectPrinterDrives", "msTSDefaultToMainPrinter", "msTSWorkDirectory", "msTSInitialProgram", "msTSProperty01", "msTSProperty02", "msTSExpireDate", "msTSLicenseVersion", "msTSManagingLS", "msDS-UserPasswordExpiryTimeComputed", "msTSExpireDate2", "msTSLicenseVersion2", "msTSManagingLS2", "msTSExpireDate3", "msTSLicenseVersion3", "msTSManagingLS3", "msTSExpireDate4", "msTSLicenseVersion4", "msTSManagingLS4", "msTSLSProperty01", "msTSLSProperty02", "msDS-ResultantPSO", "msPKI-CredentialRoamingTokens", "msTSPrimaryDesktop", "msTSSecondaryDesktops", "msDS-PrimaryComputer", "msDS-SyncServerUrl", "msDS-AssignedAuthNPolicySilo", "msDS-AuthNPolicySiloMembersBL", "msDS-AssignedAuthNPolicy", "userSMIMECertificate", "uid", "mail", "roomNumber", "photo", "manager", "homePhone", "secretary", "mobile", "pager", "audio", "jpegPhoto", "carLicense", "departmentNumber", "preferredLanguage", "userPKCS12", "labeledURI", "msSFU30Name", "msSFU30NisDomain"},
	},
	"container": {
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"mstop"},
		Required:    []string{"cn"},
		Optional:    []string{"schemaVersion", "defaultClassStore", "msDS-ObjectReference"},
	},
	"computer": {
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"user"},
		Required:    []string{},
		Optional:    []string{"cn", "networkAddress", "localPolicyFlags", "defaultLocalPolicyObject", "machineRole", "location", "netbootInitialization", "netbootGUID", "netbootMachineFilePath", "siteGUID", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "operatingSystemHotfix", "volumeCount", "physicalLocationObject", "dNSHostName", "policyReplicationFlags", "managedBy", "rIDSetReferences", "catalogs", "netbootSIFFile", "netbootMirrorDataFile", "msDS-AdditionalDnsHostName", "msDS-AdditionalSamAccountName", "msDS-ExecuteScriptPassword", "msDS-KrbTgtLink", "msDS-RevealedUsers", "msDS-NeverRevealGroup", "msDS-RevealOnDemandGroup", "msDS-RevealedList", "msDS-AuthenticatedAtDC", "msDS-isGC", "msDS-isRODC", "msDS-SiteName", "msDS-PromotionSettings", "msTPM-OwnerInformation", "msTSProperty01", "msTSProperty02", "msDS-IsUserCachableAtRodc", "msDS-HostServiceAccount", "msTSEndpointData", "msTSEndpointType", "msTSEndpointPlugin", "msTSPrimaryDesktopBL", "msTSSecondaryDesktopBL", "msTPM-TpmInformationForComputer", "msDS-GenerationId", "msImaging-ThumbprintHash", "msImaging-HashAlgorithm", "netbootDUID", "msSFU30Name", "msSFU30Aliases", "msSFU30NisDomain", "nisMapName"},
	},
	// SCHEMA: nis.schema
	"posixAccount": {
		Description: "Abstraction of an account with POSIX attributes",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "uid", "uidNumber", "gidNumber", "homeDirectory"},
		Optional:    []string{"userPassword", "loginShell", "gecos", "description"},
	},
	"shadowAccount": {
		Description: "Additional attributes for shadow passwords",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"uid"},
		Optional:    []string{"userPassword", "shadowLastChange", "shadowMin", "shadowMax", "shadowWarning", "shadowInactive", "shadowExpire", "shadowFlag", "description"},
	},
	"posixGroup": {
		Description: "Abstraction of a group of accounts",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      false,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "gidNumber"},
		Optional:    []string{"userPassword", "memberUid", "description"},
	},
	"ipService": {
		Description: "Abstraction an Internet Protocol service",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "ipServicePort", "ipServiceProtocol"},
		Optional:    []string{"description"},
	},
	"ipProtocol": {
		Description: "Abstraction of an IP protocol",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "ipProtocolNumber", "description"},
		Optional:    []string{"description"},
	},
	"oncRpc": {
		Description: "Abstraction of an ONC/RPC binding",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "oncRpcNumber", "description"},
		Optional:    []string{"description"},
	},
	"ipHost": {
		Description: "Abstraction of a host, an IP device",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "ipHostNumber"},
		Optional:    []string{"l", "description", "manager"},
	},
	"ipNetwork": {
		Description: "Abstraction of an IP network",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "ipNetworkNumber"},
		Optional:    []string{"ipNetmaskNumber", "l", "description", "manager"},
	},
	"nisNetgroup": {
		Description: "Abstraction of a netgroup",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{"nisNetgroupTriple", "memberNisNetgroup", "description"},
	},
	"nisMap": {
		Description: "A generic abstraction of a NIS map",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"nisMapName"},
		Optional:    []string{"description"},
	},
	"nisObject": {
		Description: "An entry in a NIS map",
		Type:        "STRUCTURAL",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn", "nisMapEntry", "nisMapName"},
		Optional:    []string{"description"},
	},
	"ieee802Device": {
		Description: "A device with a MAC address",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"macAddress"},
	},
	"bootableDevice": {
		Description: "A device with boot parameters",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"bootFile", "bootParameter"},
	},
	// SCHEMA: openldap.schema
	"OpenLDAPorg": {
		Description: "OpenLDAP Organizational Object",
		Type:        "UNSPECIFIED",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"organization"},
		Required:    []string{},
		Optional:    []string{"buildingName", "displayName", "labeledURI"},
	},
	"OpenLDAPou": {
		Description: "OpenLDAP Organizational Unit Object",
		Type:        "UNSPECIFIED",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"organizationalUnit"},
		Required:    []string{},
		Optional:    []string{"buildingName", "displayName", "labeledURI", "o"},
	},
	"OpenLDAPperson": {
		Description: "OpenLDAP Person",
		Type:        "UNSPECIFIED",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{"pilotPerson", "inetOrgPerson"},
		Required:    []string{"uid", "cn"},
		Optional:    []string{"givenName", "labeledURI", "o"},
	},
	"OpenLDAPdisplayableObject": {
		Description: "OpenLDAP Displayable Object",
		Type:        "AUXILIARY",
		IsContainer: false,
		Silent:      true,
		Inherit:     []string{},
		Required:    []string{},
		Optional:    []string{"displayName"},
	},
	// SCHEMA: extra
	"nsContainer": { // https://access.redhat.com/documentation/en-US/Red_Hat_Directory_Server/8.1/html/Configuration_and_Command_Reference/config-object-classes.html
		Description: "Container Entry",
		Type:        "UNSPECIFIED",
		IsContainer: true,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{"cn"},
		Optional:    []string{},
	},
	"aeZone": { // https://docs.ldap.com/specs/draft-howard-namedobject-01.txt
		Type:        "STRUCTURAL",
		IsContainer: true,
		Silent:      true,
		Inherit:     []string{"top"},
		Required:    []string{},
		Optional:    []string{"cn"},
	},
}

var LDAPAttribute = map[string]*FormElement{
	//////////////////////////
	// SCHEMA: core.schema:
	"objectClass": {
		Description: "Object classes of the entity - RFC2256",
		Order:       1,
		Datalist: func() []string {
			list := make([]string, 0)
			for key := range Schema {
				if !Schema[key].Silent {
					list = append(list, key)
				}
			}
			sort.Strings(list)
			return list
		}(),
		MultiValue: true,
	},
	"aliasedObjectName": {
		Description: "Name of aliased object - RFC2256",
	},
	"aliasedEntryName": {
		Description: "Name of aliased object - RFC2256",
	},
	"knowledgeInformation": {
		Description: "Knowledge information - RFC2256",
	},
	"cn": {
		Description: "Common name(s) for which the entity is known by - RFC2256",
		Order:       1,
	},
	"commonName": {
		Description: "Common name(s) for which the entity is known by - RFC2256",
		Order:       2,
	},
	"sn": {
		Description: "Last (family) name(s) for which the entity is known by - RFC2256",
		Order:       4,
	},
	"surname": {
		Description: "Last (family) name(s) for which the entity is known by - RFC2256",
		Order:       4,
	},
	"serialNumber": {
		Description: "Serial number of the entity - RFC2256",
	},
	"c": {
		Description: "Two-letter ISO-3166 country code - RFC4519",
	},
	"countryName": {
		Description: "Two-letter ISO-3166 country code - RFC4519",
		Order:       15,
	},
	"l": {
		Description: "Locality which this object resides in - RFC2256",
		Order:       15,
	},
	"localityName": {
		Description: "Locality which this object resides in - RFC2256",
		Order:       15,
	},
	"st": {
		Description: "State or province which this object resides in - RFC2256",
		Order:       15,
	},
	"stateOrProvinceName": {
		Description: "State or province which this object resides in - RFC2256",
		Order:       15,
	},
	"street": {
		Description: "Street address of this object - RFC2256",
		Order:       15,
	},
	"streetAddress": {
		Description: "Street address of this object - RFC2256",
		Order:       15,
	},
	"o": {
		Description: "Organization this object belongs to - RFC2256",
		Order:       10,
	},
	"organizationName": {
		Description: "Organization this object belongs to - RFC2256",
		Order:       10,
	},
	"ou": {
		Description: "Organizational unit this object belongs to - RFC2256",
		Order:       10,
	},
	"organizationalUnitName": {
		Description: "Organizational unit this object belongs to - RFC2256",
		Order:       10,
	},
	"title": {
		Description: "Title associated with the entity - RFC2256",
		Order:       20,
	},
	"description": {
		Description: "Descriptive information - RFC2256",
		Order:       5,
	},
	"searchGuide": {
		Description: "Search guide, deprecated by enhancedSearchGuide - RFC2256",
	},
	"businessCategory": {
		Description: "Business category - RFC2256",
	},
	"postalAddress": {
		Description: "Postal address - RFC2256",
		Order:       15,
	},
	"postalCode": {
		Description: "Postal code - RFC2256",
		Order:       15,
	},
	"postOfficeBox": {
		Description: "Post Office Box - RFC2256",
		Order:       15,
	},
	"physicalDeliveryOfficeName": {
		Description: "Physical Delivery Office Name - RFC2256",
		Order:       20,
	},
	"telephoneNumber": {
		Description: "Telephone Number - RFC2256",
		Order:       8,
	},
	"telexNumber": {
		Description: "Telex Number - RFC2256",
		Order:       25,
	},
	"teletexTerminalIdentifier": {
		Description: "Teletex Terminal Identifier - RFC2256",
		Order:       25,
	},
	"facsimileTelephoneNumber": {
		Description: "Facsimile (Fax) Telephone Number - RFC2256",
		Order:       25,
	},
	"fax": {
		Description: "Facsimile (Fax) Telephone Number - RFC2256",
		Order:       25,
	},
	"x121Address": {
		Description: "X.121 Address - RFC2256",
	},
	"internationaliSDNNumber": {
		Description: "International ISDN number - RFC2256",
	},
	"registeredAddress": {
		Description: "Registered postal address - RFC2256",
		Order:       15,
	},
	"destinationIndicator": {
		Description: "Destination indicator - RFC2256",
	},
	"preferredDeliveryMethod": {
		Description: "Preferred delivery method - RFC2256",
	},
	"presentationAddress": {
		Description: "Presentation address - RFC2256",
	},
	"supportedApplicationContext": {
		Description: "Supported application context - RFC2256",
	},
	"member": {
		Description: "Member of a group - RFC2256",
	},
	"owner": {
		Description: "Owner (of the object) - RFC2256",
	},
	"roleOccupant": {
		Description: "Occupant of role - RFC2256",
	},
	"seeAlso": {
		Description: "DN of related object - RFC2256",
		Order:       20,
	},
	"userPassword": {
		Description: "Password of user - RFC2256/2307",
		Order:       6,
	},
	"userCertificate": {
		Description: "X.509 user certificate, use ;binary - RFC2256",
	},
	"cACertificate": {
		Description: "X.509 CA certificate, use ;binary - RFC2256",
	},
	"authorityRevocationList": {
		Description: "X.509 authority revocation list, use ;binary - RFC2256",
	},
	"certificateRevocationList": {
		Description: "X.509 certificate revocation list, use ;binary - RFC2256",
	},
	"crossCertificatePair": {
		Description: "X.509 cross certificate pair, use ;binary - RFC2256",
	},
	"name": {
		Order: 4,
	},
	"givenName": {
		Description: "First name(s) for which the entity is known by - RFC2256",
		Order:       4,
	},
	"gn": {
		Description: "First name(s) for which the entity is known by - RFC2256",
		Order:       4,
	},
	"initials": {
		Description: "Initials of some or all of names, but not the surname(s). - RFC2256",
		Order:       20,
	},
	"generationQualifier": {
		Description: "Name qualifier indicating a generation - RFC2256",
	},
	"x500UniqueIdentifier": {
		Description: "X.500 unique identifier - RFC2256",
	},
	"dnQualifier": {
		Description: "DN qualifier - RFC2256",
	},
	"enhancedSearchGuide": {
		Description: "Enhanced search guide - RFC2256",
	},
	"protocolInformation": {
		Description: "Protocol information - RFC2256",
	},
	"distinguishedName": {
	},
	"uniqueMember": {
		Description: "Unique member of a group - RFC2256",
		Order:       9,
	},
	"houseIdentifier": {
		Description: "House identifier - RFC2256",
	},
	"supportedAlgorithms": {
		Description: "Supported algorithms - RFC2256",
	},
	"deltaRevocationList": {
		Description: "Delta revocation list; use ;binary - RFC2256",
	},
	"dmdName": {
		Description: "Name of DMD - RFC2256",
	},
	"pseudonym": {
		Description: "Pseudonym for the object - X.520(4th)",
	},
	"labeledURI": {
		Description: "Uniform Resource Identifier with optional label - RFC2079",
	},
	"uid": {
		Description: "User identifier - RFC1274",
		Order:       7,
	},
	"userid": {
		Description: "User identifier - RFC1274",
	},
	"mail": {
		Description: "RFC822 Mailbox - RFC1274",
		Order:       7,
	},
	"rfc822Mailbox": {
		Description: "RFC822 Mailbox - RFC1274",
	},
	"dc": {
		Description: "Domain component - RFC1274/2247",
		Order:       10,
	},
	"domainComponent": {
		Description: "Domain component - RFC1274/2247",
		Order:       10,
	},
	"associatedDomain": {
		Description: "Domain associated with object - RFC1274",
	},
	"email": {
		Description: "Legacy attribute for email addresses in DNs - RFC3280",
	},
	"emailAddress": {
		Description: "Legacy attribute for email addresses in DNs - RFC3280",
	},
	"pkcs9email": {
		Description: "Legacy attribute for email addresses in DNs - RFC3280",
	},
	//////////////////////////
	// SCHEMA: inetorgperson.schema
	"carLicense": {
		Description: "Vehicle license or registration plate - RFC2798",
		Order:       20,
	},
	"departmentNumber": {
		Description: "Identifies a department within an organization - RFC2798",
		Order:       20,
	},
	"displayName": {
		Description: "Preferred name to be used when displaying entries - RFC2798",
		Order:       5,
	},
	"employeeNumber": {
		Description: "Numerically identifies an employee within an organization - RFC2798",
		Order:       20,
	},
	"employeeType": {
		Description: "Type of employment for a person - RFC2798",
		Order:       20,
	},
	"jpegPhoto": {
		Description: "A JPEG image - RFC2798",
		Order:       17,
	},
	"preferredLanguage": {
		Description: "Preferred written or spoken language for a person - RFC2798",
		Order:       19,
	},
	"userSMIMECertificate": {
		Description: "PKCS7 SignedData used to support S/MIME - RFC2798",
	},
	"userPKCS12": {
		Description: "Personal identity information, a PKCS 12 PFX - RFC2798",
	},
	//////////////////////////
	// SCHEMA: collective.schema
	"c-l": {
		Description: "Locality name for the collection of entries",
	},
	"c-st": {
		Description: "State or province name for the collection of entries",
	},
	"c-street": {
		Description: "Street address for the collection of entries",
	},
	"c-o": {
		Description: "Organization name for the collection of entries",
		Order:       10,
	},
	"c-ou": {
		Description: "Organizational unit name for the collection of entries",
		Order:       10,
	},
	"c-PostalAddress": {
		Description: "Postal address for the collection of entries",
		Order:       15,
	},
	"c-PostalCode": {
		Order:       15,
		Description: "Postal code for the collection of entries",
	},
	"c-PostOfficeBox": {
		Order:       15,
		Description: "Post office box for the collection of entries",
	},
	"c-PhysicalDeliveryOfficeName": {
		Order:       20,
		Description: "Physical dlivery office name for a collection of entries.",
	},
	"c-TelephoneNumber": {
		Order:       8,
		Description: "telephone number for the collection of entries",
	},
	"c-TelexNumber": {
		Order:       25,
		Description: "Telex number for the collection of entries",
	},
	"c-FacsimileTelephoneNumber": {
		Description: "Facsimile telephone number for a collection of entries.",
	},
	"c-InternationalISDNNumber": {
		Description: "International ISDN number for the collection of entries",
	},
	//////////////////////////
	// SCHEMA: corba.schema
	"corbaIor": {
		Description: "Stringified interoperable object reference of a CORBA object",
	},
	"corbaRepositoryId": {
		Description: "Repository ids of interfaces implemented by a CORBA object",
	},
	//////////////////////////
	// SCHEMA: cosine.schema
	"textEncodedORAddress": {
		Description: "Text encoding of an X.400 O/R address, as specified in RFC 987",
	},
	"info": {
		Description: "General information - RFC1274",
	},
	"drink": {
		Description: "Favorite drink - RFC1274",
	},
	"favouriteDrink": {
		Description: "Favorite drink - RFC1274",
	},
	"roomNumber": {
		Description: "Room number - RFC1274",
		Order:       20,
	},
	"photo": {
		Description: "Photo (G3 fax) - RFC1274",
		Order:       17,
	},
	"userClass": {
		Description: "Category of user - RFC1274",
	},
	"host": {
		Description: "Host computer - RFC1274",
	},
	"manager": {
		Description: "DN of manager - RFC1274",
		Order:       20,
	},
	"documentIdentifier": {
		Description: "Unique identifier of document - RFC1274",
	},
	"documentTitle": {
		Description: "Title of document - RFC1274",
	},
	"documentVersion": {
		Description: "Version of document - RFC1274",
	},
	"documentAuthor": {
		Description: "DN of author of document - RFC1274",
	},
	"documentLocation": {
		Description: "Location of document original - RFC1274",
	},
	"homePhone": {
		Description: "Home telephone number - RFC1274",
		Order:       8,
	},
	"homeTelephoneNumber": {
		Description: "Home telephone number - RFC1274",
	},
	"secretary": {
		Description: "DN of secretary - RFC1274",
	},
	"otherMailbox": {
	},
	"lastModifiedTime": {
		Description: "Time of last modify, replaced by modifyTimestamp - RFC1274",
	},
	"lastModifiedBy": {
		Description: "Last modifier, replaced by modifiersName - RFC1274",
	},
	"aRecord": {
		Description: "Type A (Address) DNS resource record",
	},
	"mDRecord": {
	},
	"mXRecord": {
		Description: "Mail Exchange DNS resource record",
	},
	"nSRecord": {
		Description: "Name Server DNS resource record",
	},
	"sOARecord": {
		Description: "Start of Authority DNS resource record",
	},
	"cNAMERecord": {
		Description: "CNAME (Canonical Name) DNS resource record",
	},
	"associatedName": {
		Description: "DN of entry associated with domain - RFC1274",
	},
	"homePostalAddress": {
		Description: "Home postal address - RFC1274",
		Order:       15,
	},
	"personalTitle": {
		Description: "Personal title - RFC1274",
	},
	"mobile": {
		Description: "Mobile telephone number - RFC1274",
		Order:       8,
	},
	"mobileTelephoneNumber": {
		Description: "Mobile telephone number - RFC1274",
		Order:       8,
	},
	"pager": {
		Description: "Pager telephone number - RFC1274",
		Order:       20,
	},
	"pagerTelephoneNumber": {
		Description: "Pager telephone number - RFC1274",
		Order:       20,
	},
	"co": {
		Description: "Friendly country name - RFC1274",
	},
	"friendlyCountryName": {
		Description: "Friendly country name - RFC1274",
	},
	"uniqueIdentifier": {
		Description: "Unique identifer - RFC1274",
	},
	"organizationalStatus": {
		Description: "Organizational status - RFC1274",
	},
	"janetMailbox": {
		Description: "Janet mailbox - RFC1274",
	},
	"mailPreferenceOption": {
		Description: "Mail preference option - RFC1274",
	},
	"buildingName": {
		Description: "Name of building - RFC1274",
	},
	"dSAQuality": {
		Description: "DSA Quality - RFC1274",
	},
	"singleLevelQuality": {
		Description: "Single Level Quality - RFC1274",
	},
	"subtreeMinimumQuality": {
		Description: "Subtree Minimum Quality - RFC1274",
	},
	"subtreeMaximumQuality": {
		Description: "Subtree Maximum Quality - RFC1274",
	},
	"personalSignature": {
		Description: "Personal Signature (G3 fax) - RFC1274",
	},
	"dITRedirect": {
		Description: "DIT Redirect - RFC1274",
	},
	"audio": {
		Description: "Audio (u-law) - RFC1274",
	},
	"documentPublisher": {
		Description: "Publisher of document - RFC1274",
	},
	//////////////////////////
	// SCHEMA: duaconf.schema
	"defaultServerList": {
		Description: "Default LDAP server host address used by a DUA",
	},
	"defaultSearchBase": {
		Description: "Default LDAP base DN used by a DUA",
	},
	"preferredServerList": {
		Description: "Preferred LDAP server host addresses to be used by a DUA",
	},
	"searchTimeLimit": {
		Description: "Maximum time in seconds a DUA should allow for a search to complete",
	},
	"bindTimeLimit": {
		Description: "Maximum time in seconds a DUA should allow for the bind operation to complete",
	},
	"followReferrals": {
		Description: "Tells DUA if it should follow referrals returned by a DSA search result",
	},
	"dereferenceAliases": {
		Description: "Tells DUA if it should dereference aliases",
	},
	"authenticationMethod": {
		Description: "A keystring which identifies the type of authentication method used to contact the DSA",
	},
	"profileTTL": {
		Description: "Time to live, in seconds, before a client DUA should re-read this configuration profile",
	},
	"serviceSearchDescriptor": {
		Description: "LDAP search descriptor list used by a DUA",
	},
	"attributeMap": {
		Description: "Attribute mappings used by a DUA",
	},
	"credentialLevel": {
		Description: "Identifies type of credentials a DUA should use when binding to the LDAP server",
	},
	"objectclassMap": {
		Description: "Objectclass mappings used by a DUA",
	},
	"defaultSearchScope": {
		Description: "Default search scope used by a DUA",
	},
	"serviceCredentialLevel": {
		Description: "Identifies type of credentials a DUA should use when binding to the LDAP server for a specific service",
	},
	"serviceAuthenticationMethod": {
		Description: "Authentication method used by a service of the DUA",
	},
	//////////////////////////
	// SCHEMA: dyngroup.schema
	"memberURL": {
		Description: "Identifies an URL associated with each member of a group. Any type of labeled URL can be used.",
	},
	"dgIdentity": {
		Description: "Identity to use when processing the memberURL",
	},
	"dgAuthz": {
		Description: "Optional authorization rules that determine who is allowed to assume the dgIdentity",
	},
	//////////////////////////
	// SCHEMA: java.schema
	"javaClassName": {
		Description: "Fully qualified name of distinguished Java class or interface",
	},
	"javaCodebase": {
		Description: "URL(s) specifying the location of class definition",
	},
	"javaClassNames": {
		Description: "Fully qualified Java class or interface name",
	},
	"javaSerializedData": {
		Description: "Serialized form of a Java object",
	},
	"javaFactory": {
		Description: "Fully qualified Java class name of a JNDI object factory",
	},
	"javaReferenceAddress": {
		Description: "Addresses associated with a JNDI Reference",
	},
	"javaDoc": {
		Description: "The Java documentation for the class",
	},
	//////////////////////////
	// SCHEMA: misc.schema
	"mailLocalAddress": {
		Description: "RFC822 email address of this recipient",
	},
	"mailHost": {
		Description: "FQDN of the SMTP/MTA of this recipient",
	},
	"mailRoutingAddress": {
		Description: "RFC822 routing address of this recipient",
	},
	"rfc822MailMember": {
		Description: "Rfc822 mail address of group member(s)",
	},
	//////////////////////////
	// SCHEMA: msuser.schema
	"ownerBL": {
	},
	"msCOM-PartitionSetLink": {
	},
	"msCOM-UserLink": {
	},
	"msDS-Approx-Immed-Subordinates": {
	},
	"msDS-NCReplCursors": {
	},
	"msDS-NCReplInboundNeighbors": {
	},
	"msDS-NCReplOutboundNeighbors": {
	},
	"msDS-ReplAttributeMetaData": {
	},
	"msDS-ReplValueMetaData": {
	},
	"msDS-NonMembers": {
	},
	"msDS-NonMembersBL": {
	},
	"msDS-MembersForAzRole": {
	},
	"msDS-MembersForAzRoleBL": {
	},
	"msDS-OperationsForAzTask": {
	},
	"msDS-OperationsForAzTaskBL": {
	},
	"msDS-TasksForAzTask": {
	},
	"msDS-TasksForAzTaskBL": {
	},
	"msDS-OperationsForAzRole": {
	},
	"msDS-OperationsForAzRoleBL": {
	},
	"msDS-TasksForAzRole": {
	},
	"msDS-TasksForAzRoleBL": {
	},
	"msDs-masteredBy": {
	},
	"msDS-ObjectReference": {
	},
	"msDS-ObjectReferenceBL": {
	},
	"msDS-PrincipalName": {
	},
	"msDS-RevealedDSAs": {
	},
	"msDS-KrbTgtLinkBl": {
	},
	"msDS-IsFullReplicaFor": {
	},
	"msDS-IsDomainFor": {
	},
	"msDS-IsPartialReplicaFor": {
	},
	"msDS-AuthenticatedToAccountlist": {
	},
	"msDS-AuthenticatedAtDC": {
	},
	"msDS-RevealedListBL": {
	},
	"msDS-NC-RO-Replica-Locations-BL": {
	},
	"msDS-PSOApplied": {
	},
	"msDS-NcType": {
	},
	"msDS-OIDToGroupLinkBl": {
	},
	"isRecycled": {
	},
	"msDS-LocalEffectiveDeletionTime": {
	},
	"msDS-LocalEffectiveRecycleTime": {
	},
	"msDS-LastKnownRDN": {
	},
	"msDS-EnabledFeatureBL": {
	},
	"msDS-MembersOfResourcePropertyListBL": {
	},
	"msDS-ValueTypeReferenceBL": {
	},
	"msDS-TDOIngressBL": {
	},
	"msDS-TDOEgressBL": {
	},
	"msDS-parentdistname": {
	},
	"msDS-ReplValueMetaDataExt": {
	},
	"msds-memberOfTransitive": {
	},
	"msds-memberTransitive": {
	},
	"msSFU30PosixMemberOf": {
	},
	"msDFSR-MemberReferenceBL": {
	},
	"msDFSR-ComputerReferenceBL": {
	},
	"msDS-AzLDAPQuery": {
	},
	"msDS-AzBizRuleLanguage": {
	},
	"msDS-AzLastImportedBizRulePath": {
	},
	"msDS-AzApplicationData": {
	},
	"msDS-AzObjectGuid": {
	},
	"msDS-AzGenericData": {
	},
	"msDS-PrimaryComputer": {
	},
	"msSFU30Name": {
	},
	"msSFU30NisDomain": {
	},
	"msSFU30PosixMember": {
	},
	"msCOM-UserPartitionSetLink": {
	},
	"msDS-Cached-Membership": {
	},
	"msDS-Cached-Membership-Time-Stamp": {
	},
	"msDS-Site-Affinity": {
	},
	"msDS-User-Account-Control-Computed": {
	},
	"lastLogonTimestamp": {
	},
	"msIIS-FTPRoot": {
	},
	"msIIS-FTPDir": {
	},
	"msDRM-IdentityCertificate": {
	},
	"msDS-SourceObjectDN": {
	},
	"msPKIRoamingTimeStamp": {
	},
	"msPKIDPAPIMasterKeys": {
	},
	"msPKIAccountCredentials": {
	},
	"msRADIUS-FramedInterfaceId": {
	},
	"msRADIUS-SavedFramedInterfaceId": {
	},
	"msRADIUS-FramedIpv6Prefix": {
	},
	"msRADIUS-SavedFramedIpv6Prefix": {
	},
	"msRADIUS-FramedIpv6Route": {
	},
	"msRADIUS-SavedFramedIpv6Route": {
	},
	"msDS-SecondaryKrbTgtNumber": {
	},
	"msDS-SupportedEncryptionTypes": {
	},
	"msDS-LastSuccessfulInteractiveLogonTime": {
	},
	"msDS-LastFailedInteractiveLogonTime": {
	},
	"msDS-FailedInteractiveLogonCount": {
	},
	"msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon": {
	},
	"msTSProfilePath": {
	},
	"msTSHomeDirectory": {
	},
	"msTSHomeDrive": {
	},
	"msTSAllowLogon": {
	},
	"msTSRemoteControl": {
	},
	"msTSMaxDisconnectionTime": {
	},
	"msTSMaxConnectionTime": {
	},
	"msTSMaxIdleTime": {
	},
	"msTSReconnectionAction": {
	},
	"msTSBrokenConnectionAction": {
	},
	"msTSConnectClientDrives": {
	},
	"msTSConnectPrinterDrives": {
	},
	"msTSDefaultToMainPrinter": {
	},
	"msTSWorkDirectory": {
	},
	"msTSInitialProgram": {
	},
	"msTSProperty01": {
	},
	"msTSProperty02": {
	},
	"msTSExpireDate": {
	},
	"msTSLicenseVersion": {
	},
	"msTSManagingLS": {
	},
	"msDS-UserPasswordExpiryTimeComputed": {
	},
	"msTSManagingLS4": {
	},
	"msTSManagingLS3": {
	},
	"msTSManagingLS2": {
	},
	"msTSExpireDate4": {
	},
	"msTSExpireDate3": {
	},
	"msTSExpireDate2": {
	},
	"msTSLicenseVersion3": {
	},
	"msTSLicenseVersion2": {
	},
	"msTSLicenseVersion4": {
	},
	"msTSLSProperty01": {
	},
	"msTSLSProperty02": {
	},
	"msDS-ResultantPSO": {
	},
	"msPKI-CredentialRoamingTokens": {
	},
	"msTSPrimaryDesktop": {
	},
	"msTSSecondaryDesktops": {
	},
	"msDS-SyncServerUrl": {
	},
	"msDS-AssignedAuthNPolicySilo": {
	},
	"msDS-AuthNPolicySiloMembersBL": {
	},
	"msDS-AssignedAuthNPolicy": {
	},
	"msDS-Behavior-Version": {
	},
	"msDS-PerUserTrustQuota": {
	},
	"msDS-AllUsersTrustQuota": {
	},
	"msDS-PerUserTrustTombstonesQuota": {
	},
	"msDS-AdditionalDnsHostName": {
	},
	"msDS-AdditionalSamAccountName": {
	},
	"msDS-ExecuteScriptPassword": {
	},
	"msDS-KrbTgtLink": {
	},
	"msDS-RevealedUsers": {
	},
	"msDS-NeverRevealGroup": {
	},
	"msDS-RevealOnDemandGroup": {
	},
	"msDS-RevealedList": {
	},
	"msDS-isGC": {
	},
	"msDS-isRODC": {
	},
	"msDS-SiteName": {
	},
	"msDS-PromotionSettings": {
	},
	"msTPM-OwnerInformation": {
	},
	"msDS-IsUserCachableAtRodc": {
	},
	"msDS-HostServiceAccount": {
	},
	"msTSEndpointData": {
	},
	"msTSEndpointType": {
	},
	"msTSEndpointPlugin": {
	},
	"msTSPrimaryDesktopBL": {
	},
	"msTSSecondaryDesktopBL": {
	},
	"msTPM-TpmInformationForComputer": {
	},
	"msDS-GenerationId": {
	},
	"msImaging-ThumbprintHash": {
	},
	"msImaging-HashAlgorithm": {
	},
	"netbootDUID": {
	},
	"msSFU30Aliases": {
	},
	"netbootNewMachineOU": {
	},
	"builtinCreationTime": {
	},
	"pKIEnrollmentAccess": {
	},
	"pKIExtendedKeyUsage": {
	},
	"msNPCalledStationID": {
	},
	"initialAuthIncoming": {
	},
	"objectClassCategory": {
	},
	"generatedConnection": {
	},
	"allowedChildClasses": {
	},
	"machineArchitecture": {
	},
	"aCSMaxPeakBandwidth": {
	},
	"marshalledInterface": {
	},
	"rIDManagerReference": {
	},
	"aCSEnableACSService": {
	},
	"mSMQRoutingService": {
	},
	"mS-SQL-AllowQueuedUpdatingSubscription": {
	},
	"primaryTelexNumber": {
	},
	"userAccountControl": {
	},
	"shellPropertyPages": {
	},
	"replUpToDateVector": {
	},
	"fRSDirectoryFilter": {
	},
	"printSeparatorFile": {
	},
	"pKIMaxIssuingDepth": {
	},
	"accountNameHistory": {
	},
	"mS-SQL-GPSLongitude": {
	},
	"adminPropertyPages": {
	},
	"securityIdentifier": {
	},
	"groupMembershipSAM": {
	},
	"serviceDNSNameType": {
	},
	"meetingIsEncrypted": {
	},
	"mS-SQL-Applications": {
	},
	"lastUpdateSequence": {
	},
	"lastContentIndexed": {
	},
	"meetingDescription": {
	},
	"fRSTimeLastCommand": {
	},
	"monikerDisplayName": {
	},
	"requiredCategories": {
	},
	"upgradeProductCode": {
	},
	"aCSMaxNoOfLogFiles": {
	},
	"mS-SQL-CharacterSet": {
	},
	"meetingContactInfo": {
	},
	"mS-SQL-CreationDate": {
	},
	"domainPolicyObject": {
	},
	"dhcpObjDescription": {
	},
	"meetingApplication": {
	},
	"defaultHidingValue": {
	},
	"fRSMemberReference": {
	},
	"dhcpIdentification": {
	},
	"trustAuthOutgoing": {
	},
	"systemMustContain": {
	},
	"primaryGroupToken": {
	},
	"rpcNsProfileEntry": {
	},
	"trustAuthIncoming": {
	},
	"mSMQPrevSiteGates": {
	},
	"queryPolicyObject": {
	},
	"optionDescription": {
	},
	"aCSMaximumSDUSize": {
	},
	"nonSecurityMember": {
	},
	"fRSReplicaSetType": {
	},
	"aCSTotalNoOfFlows": {
	},
	"possibleInferiors": {
	},
	"netbootMaxClients": {
	},
	"mS-SQL-GPSLatitude": {
	},
	"aCSPermissionBits": {
	},
	"mSMQTransactional": {
	},
	"mS-SQL-Description": {
	},
	"allowedAttributes": {
	},
	"fRSFaultCondition": {
	},
	"tombstoneLifetime": {
	},
	"remoteStorageGUID": {
	},
	"showInAddressBook": {
	},
	"defaultClassStore": {
	},
	"meetingOriginator": {
	},
	"userPrincipalName": {
	},
	"aCSMinimumLatency": {
	},
	"isPrivilegeHolder": {
	},
	"fRSReplicaSetGUID": {
	},
	"rIDAllocationPool": {
	},
	"pKIDefaultKeySpec": {
	},
	"dynamicLDAPServer": {
	},
	"serverReferenceBL": {
	},
	"fRSServiceCommand": {
	},
	"sDRightsEffective": {
	},
	"proxiedObjectName": {
	},
	"meetingRecurrence": {
	},
	"cOMTreatAsClassId": {
	},
	"globalAddressList": {
	},
	"extendedClassInfo": {
	},
	"machineWidePolicy": {
	},
	"foreignIdentifier": {
	},
	"dNReferenceUpdate": {
	},
	"trustPosixOffset": {
	},
	"enabledConnection": {
	},
	"ipsecNFAReference": {
	},
	"userWorkstations": {
	},
	"garbageCollPeriod": {
	},
	"mSMQComputerType": {
	},
	"logonWorkstation": {
	},
	"mSMQJournalQuota": {
	},
	"remoteSourceType": {
	},
	"pwdHistoryLength": {
	},
	"mSMQBasePriority": {
	},
	"systemMayContain": {
	},
	"mS-SQL-ThirdParty": {
	},
	"mSMQQueueNameExt": {
	},
	"fRSUpdateTimeout": {
	},
	"mSMQPrivacyLevel": {
	},
	"shellContextMenu": {
	},
	"wellKnownObjects": {
	},
	"transportDLLName": {
	},
	"qualityOfService": {
	},
	"lockoutThreshold": {
	},
	"remoteServerName": {
	},
	"previousParentCA": {
	},
	"dSUIShellMaximum": {
	},
	"notificationList": {
	},
	"addressBookRoots": {
	},
	"fRSPrimaryMember": {
	},
	"meetingStartTime": {
	},
	"mSMQSiteGatesMig": {
	},
	"dhcpReservations": {
	},
	"adminContextMenu": {
	},
	"pKIOverlapPeriod": {
	},
	"winsockAddresses": {
	},
	"mSMQAuthenticate": {
	},
	"dSUIAdminMaximum": {
	},
	"appSchemaVersion": {
	},
	"serviceClassInfo": {
	},
	"aCSEventLogLevel": {
	},
	"userSharedFolder": {
	},
	"domainWidePolicy": {
	},
	"rIDSetReferences": {
	},
	"canUpgradeScript": {
	},
	"classDisplayName": {
	},
	"adminDescription": {
	},
	"lSAModifiedCount": {
	},
	"serviceClassName": {
	},
	"localPolicyFlags": {
	},
	"rpcNsInterfaceID": {
	},
	"adminDisplayName": {
	},
	"nameServiceFlags": {
	},
	"meetingBandwidth": {
	},
	"domainIdentifier": {
	},
	"rIDAvailablePool": {
	},
	"legacyExchangeDN": {
	},
	"trustAttributes": {
	},
	"fRSRootSecurity": {
	},
	"superiorDNSRoot": {
	},
	"printMaxYExtent": {
	},
	"printMaxXExtent": {
	},
	"printMinYExtent": {
	},
	"printMinXExtent": {
	},
	"attributeSyntax": {
	},
	"printAttributes": {
	},
	"groupAttributes": {
	},
	"fileExtPriority": {
	},
	"mSMQServiceType": {
	},
	"operatingSystem": {
	},
	"mS-SQL-SortOrder": {
	},
	"versionNumberLo": {
	},
	"msRRASAttribute": {
	},
	"lastKnownParent": {
	},
	"shortServerName": {
	},
	"lockoutDuration": {
	},
	"defaultPriority": {
	},
	"rpcNsEntryFlags": {
	},
	"optionsLocation": {
	},
	"versionNumberHi": {
	},
	"rpcNsAnnotation": {
	},
	"purportedSearch": {
	},
	"aCSDSBMPriority": {
	},
	"mSMQSiteForeign": {
	},
	"currentLocation": {
	},
	"meetingProtocol": {
	},
	"publicKeyPolicy": {
	},
	"mS-SQL-Publisher": {
	},
	"createWizardExt": {
	},
	"mS-SQL-Clustered": {
	},
	"volTableIdxGUID": {
	},
	"currentParentCA": {
	},
	"seqNotification": {
	},
	"serverReference": {
	},
	"msNPAllowDialin": {
	},
	"mS-SQL-GPSHeight": {
	},
	"mS-SQL-AppleTalk": {
	},
	"linkTrackSecret": {
	},
	"dnsAllowDynamic": {
	},
	"badPasswordTime": {
	},
	"privilegeHolder": {
	},
	"printMediaReady": {
	},
	"printMACAddress": {
	},
	"lSACreationTime": {
	},
	"meetingLocation": {
	},
	"aCSIdentityName": {
	},
	"mS-DS-CreatorSID": {
	},
	"mS-SQL-NamedPipe": {
	},
	"lDAPAdminLimits": {
	},
	"lDAPDisplayName": {
	},
	"applicationName": {
	},
	"pendingParentCA": {
	},
	"aCSCacheTimeout": {
	},
	"meetingLanguage": {
	},
	"aCSDSBMDeadTime": {
	},
	"cACertificateDN": {
	},
	"userParameters": {
	},
	"trustDirection": {
	},
	"mSMQQueueQuota": {
	},
	"mSMQEncryptKey": {
	},
	"terminalServer": {
	},
	"printStartTime": {
	},
	"syncWithObject": {
	},
	"groupsToIgnore": {
	},
	"syncMembership": {
	},
	"syncAttributes": {
	},
	"nextLevelStore": {
	},
	"sAMAccountType": {
	},
	"mS-SQL-Keywords": {
	},
	"proxyAddresses": {
	},
	"bytesPerMinute": {
	},
	"printMaxCopies": {
	},
	"primaryGroupID": {
	},
	"nTGroupMembers": {
	},
	"mSMQDsServices": {
	},
	"fRSVersionGUID": {
	},
	"fRSWorkingPath": {
	},
	"otherTelephone": {
	},
	"otherHomePhone": {
	},
	"oEMInformation": {
	},
	"networkAddress": {
	},
	"mSMQDigestsMig": {
	},
	"meetingKeyword": {
	},
	"lDAPIPDenyList": {
	},
	"installUiLevel": {
	},
	"gPCFileSysPath": {
	},
	"fRSStagingPath": {
	},
	"auxiliaryClass": {
	},
	"accountExpires": {
	},
	"dhcpProperties": {
	},
	"desktopProfile": {
	},
	"aCSServiceType": {
	},
	"assocNTAccount": {
	},
	"creationWizard": {
	},
	"cOMOtherProgId": {
	},
	"auditingPolicy": {
	},
	"privilegeValue": {
	},
	"mS-SQL-Location": {
	},
	"pKIDefaultCSPs": {
	},
	"printShareName": {
	},
	"isSingleValued": {
	},
	"domainCrossRef": {
	},
	"netbootSIFFile": {
	},
	"cOMUniqueLIBID": {
	},
	"serviceDNSName": {
	},
	"objectCategory": {
	},
	"serviceClassID": {
	},
	"dhcpUpdateTime": {
	},
	"sAMAccountName": {
	},
	"meetingEndTime": {
	},
	"mS-SQL-Language": {
	},
	"aCSDSBMRefresh": {
	},
	"mS-SQL-Database": {
	},
	"cOMInterfaceID": {
	},
	"mS-SQL-AllowKnownPullSubscription": {
	},
	"mS-SQL-AllowAnonymousSubscription": {
	},
	"managedObjects": {
	},
	"possSuperiors": {
	},
	"transportType": {
	},
	"groupPriority": {
	},
	"rpcNsPriority": {
	},
	"mSMQQueueType": {
	},
	"versionNumber": {
	},
	"uSNLastObjRem": {
	},
	"templateRoots": {
	},
	"pwdProperties": {
	},
	"printNumberUp": {
	},
	"fRSExtensions": {
	},
	"printRateUnit": {
	},
	"msiScriptSize": {
	},
	"printSpooling": {
	},
	"queryPolicyBL": {
	},
	"proxyLifetime": {
	},
	"operatorCount": {
	},
	"netbootServer": {
	},
	"fSMORoleOwner": {
	},
	"driverVersion": {
	},
	"mS-SQL-Version": {
	},
	"mSMQNameStyle": {
	},
	"schemaVersion": {
	},
	"directReports": {
	},
	"addressSyntax": {
	},
	"printFormName": {
	},
	"msiScriptPath": {
	},
	"aCSServerList": {
	},
	"moveTreeState": {
	},
	"mSMQSiteGates": {
	},
	"mSMQDsService": {
	},
	"objectVersion": {
	},
	"dNSTombstoned": {
	},
	"mSMQLongLived": {
	},
	"fRSLevelLimit": {
	},
	"msiScriptName": {
	},
	"dhcpUniqueKey": {
	},
	"extensionName": {
	},
	"rpcNsBindings": {
	},
	"printBinNames": {
	},
	"replicaSource": {
	},
	"printLanguage": {
	},
	"mS-SQL-Contact": {
	},
	"nTMixedDomain": {
	},
	"fRSFileFilter": {
	},
	"birthLocation": {
	},
	"friendlyNames": {
	},
	"ipsecDataType": {
	},
	"meetingRating": {
	},
	"indexedScopes": {
	},
	"rpcNsObjectID": {
	},
	"modifiedCount": {
	},
	"oMObjectClass": {
	},
	"aCSPolicyName": {
	},
	"timeVolChange": {
	},
	"currMachineId": {
	},
	"schemaFlagsEx": {
	},
	"validAccesses": {
	},
	"domainReplica": {
	},
	"mSMQInterval2": {
	},
	"mSMQInterval1": {
	},
	"canonicalName": {
	},
	"ntPwdHistory": {
	},
	"trustPartner": {
	},
	"lmPwdHistory": {
	},
	"mS-SQL-Status": {
	},
	"USNIntersite": {
	},
	"netbootTools": {
	},
	"priorSetTime": {
	},
	"mS-SQL-Memory": {
	},
	"mSMQServices": {
	},
	"currentValue": {
	},
	"siteLinkList": {
	},
	"remoteSource": {
	},
	"setupCommand": {
	},
	"dSHeuristics": {
	},
	"replInterval": {
	},
	"printEndTime": {
	},
	"instanceType": {
	},
	"otherIpPhone": {
	},
	"mSMQSiteName": {
	},
	"meetingOwner": {
	},
	"printCollate": {
	},
	"defaultGroup": {
	},
	"minPwdLength": {
	},
	"netbootSCPBL": {
	},
	"mhsORAddress": {
	},
	"rpcNsCodeset": {
	},
	"hasMasterNCs": {
	},
	"mSMQMigrated": {
	},
	"dSASignature": {
	},
	"invocationId": {
	},
	"cOMTypelibId": {
	},
	"creationTime": {
	},
	"meetingScope": {
	},
	"volTableGUID": {
	},
	"siteObjectBL": {
	},
	"aCSTimeOfDay": {
	},
	"aCSDirection": {
	},
	"maxTicketAge": {
	},
	"schemaUpdate": {
	},
	"minTicketAge": {
	},
	"ipsecNegotiationPolicyReference": {
	},
	"helpFileName": {
	},
	"schemaIDGUID": {
	},
	"createDialog": {
	},
	"mSMQNt4Flags": {
	},
	"packageFlags": {
	},
	"wWWHomePage": {
	},
	"volumeCount": {
	},
	"printStatus": {
	},
	"uPNSuffixes": {
	},
	"trustParent": {
	},
	"tokenGroups": {
	},
	"systemFlags": {
	},
	"syncWithSID": {
	},
	"dNSProperty": {
	},
	"superScopes": {
	},
	"sPNMappings": {
	},
	"printNotify": {
	},
	"printMemory": {
	},
	"serverState": {
	},
	"mSMQVersion": {
	},
	"rIDUsedPool": {
	},
	"queryFilter": {
	},
	"printerName": {
	},
	"preferredOU": {
	},
	"primaryInternationalISDNNumber": {
	},
	"oMTIndxGuid": {
	},
	"mSMQUserSid": {
	},
	"fRSRootPath": {
	},
	"mSMQJournal": {
	},
	"contextMenu": {
	},
	"aCSPriority": {
	},
	"mSMQSignKey": {
	},
	"netbootGUID": {
	},
	"mSMQOwnerID": {
	},
	"mustContain": {
	},
	"dnsAllowXFR": {
	},
	"mS-SQL-Vines": {
	},
	"mSMQDigests": {
	},
	"lockoutTime": {
	},
	"lastSetTime": {
	},
	"countryCode": {
	},
	"mS-SQL-TCPIP": {
	},
	"mSMQForeign": {
	},
	"meetingType": {
	},
	"dhcpOptions": {
	},
	"dhcpServers": {
	},
	"assetNumber": {
	},
	"addressType": {
	},
	"mSMQCSPName": {
	},
	"msiFileList": {
	},
	"dNSHostName": {
	},
	"dhcpSubnets": {
	},
	"pKIKeyUsage": {
	},
	"attributeID": {
	},
	"objectCount": {
	},
	"timeRefresh": {
	},
	"profilePath": {
	},
	"productCode": {
	},
	"otherMobile": {
	},
	"badPwdCount": {
	},
	"mS-SQL-Build": {
	},
	"nETBIOSName": {
	},
	"mS-SQL-Alias": {
	},
	"maxRenewAge": {
	},
	"treatAsLeaf": {
	},
	"mSMQNt4Stub": {
	},
	"packageType": {
	},
	"isEphemeral": {
	},
	"dMDLocation": {
	},
	"dhcpClasses": {
	},
	"forceLogoff": {
	},
	"whenCreated": {
	},
	"meetingName": {
	},
	"mailAddress": {
	},
	"meetingBlob": {
	},
	"machineRole": {
	},
	"searchFlags": {
	},
	"whenChanged": {
	},
	"dhcpObjName": {
	},
	"aCSMaxAggregatePeakRatePerUser": {
	},
	"packageName": {
	},
	"systemOnly": {
	},
	"mSMQOSType": {
	},
	"queryPoint": {
	},
	"printOwner": {
	},
	"uSNCreated": {
	},
	"siteServer": {
	},
	"rpcNsGroup": {
	},
	"sIDHistory": {
	},
	"fRSVersion": {
	},
	"logonHours": {
	},
	"netbootAnswerOnlyValidClients": {
	},
	"pwdLastSet": {
	},
	"printColor": {
	},
	"mS-SQL-Type": {
	},
	"fromServer": {
	},
	"serverRole": {
	},
	"priorValue": {
	},
	"logonCount": {
	},
	"unicodePwd": {
	},
	"subClassOf": {
	},
	"mS-SQL-Size": {
	},
	"privateKey": {
	},
	"siteObject": {
	},
	"scriptPath": {
	},
	"serverName": {
	},
	"mSMQSiteID": {
	},
	"rightsGuid": {
	},
	"rIDNextRID": {
	},
	"meetingURL": {
	},
	"addressEntryDisplayTableMSDOS": {
	},
	"maxStorage": {
	},
	"rangeUpper": {
	},
	"rangeLower": {
	},
	"otherPager": {
	},
	"isMemberOfPartialAttributeSet": {
	},
	"parentGUID": {
	},
	"department": {
	},
	"mayContain": {
	},
	"adminCount": {
	},
	"lastLogoff": {
	},
	"masteredBy": {
	},
	"employeeID": {
	},
	"dhcpMaxKey": {
	},
	"driverName": {
	},
	"mS-SQL-Name": {
	},
	"categoryId": {
	},
	"additionalTrustedServiceNames": {
	},
	"scopeFlags": {
	},
	"categories": {
	},
	"netbootNewMachineNamingPolicy": {
	},
	"cOMClassID": {
	},
	"uSNChanged": {
	},
	"objectGUID": {
	},
	"dhcpRanges": {
	},
	"schemaInfo": {
	},
	"otherFacsimileTelephoneNumber": {
	},
	"machinePasswordChangeInterval": {
	},
	"rootTrust": {
	},
	"trustType": {
	},
	"groupType": {
	},
	"uSNSource": {
	},
	"mSMQQuota": {
	},
	"mSMQSites": {
	},
	"fromEntry": {
	},
	"mS-SQL-SPX": {
	},
	"gPOptions": {
	},
	"msiScript": {
	},
	"printRate": {
	},
	"cRLPartitionedRevocationList": {
	},
	"assistant": {
	},
	"fRSDSPoll": {
	},
	"partialAttributeDeletionList": {
	},
	"lastLogon": {
	},
	"governsID": {
	},
	"appliesTo": {
	},
	"eFSPolicy": {
	},
	"uASCompat": {
	},
	"prefixMap": {
	},
	"isDefunct": {
	},
	"dhcpSites": {
	},
	"iPSECNegotiationPolicyAction": {
	},
	"dnsRecord": {
	},
	"cOMProgID": {
	},
	"homeDrive": {
	},
	"meetingIP": {
	},
	"aCSNonReservedMinPolicedSize": {
	},
	"dhcpState": {
	},
	"mSMQLabel": {
	},
	"maxPwdAge": {
	},
	"minPwdAge": {
	},
	"cRLObject": {
	},
	"objectSid": {
	},
	"meetingID": {
	},
	"ipsecName": {
	},
	"isDeleted": {
	},
	"aCSAggregateTokenRatePerUser": {
	},
	"ipsecData": {
	},
	"domainCAs": {
	},
	"cAConnect": {
	},
	"printMaxResolutionSupported": {
	},
	"dhcpFlags": {
	},
	"helpData16": {
	},
	"managedBy": {
	},
	"helpData32": {
	},
	"mSMQSite2": {
	},
	"mSMQSite1": {
	},
	"replTopologyStayOfExecution": {
	},
	"allowedChildClassesEffective": {
	},
	"oMSyntax": {
	},
	"priority": {
	},
	"keywords": {
	},
	"mSMQCost": {
	},
	"siteList": {
	},
	"revision": {
	},
	"repsFrom": {
	},
	"userCert": {
	},
	"mSMQQMID": {
	},
	"portName": {
	},
	"netbootLocallyInstalledOSes": {
	},
	"division": {
	},
	"aCSMaxSizeOfRSVPAccountFile": {
	},
	"dhcpType": {
	},
	"wbemPath": {
	},
	"siteGUID": {
	},
	"rDNAttID": {
	},
	"aCSRSVPAccountFilesLocation": {
	},
	"mSMQDependentClientServices": {
	},
	"location": {
	},
	"fRSFlags": {
	},
	"iconPath": {
	},
	"cAWEBURL": {
	},
	"mscopeId": {
	},
	"treeName": {
	},
	"schedule": {
	},
	"parentCA": {
	},
	"cOMCLSID": {
	},
	"catalogs": {
	},
	"memberOf": {
	},
	"cAUsages": {
	},
	"dhcpMask": {
	},
	"flatName": {
	},
	"domainID": {
	},
	"localeID": {
	},
	"codePage": {
	},
	"aCSEnableRSVPMessageLogging": {
	},
	"printOrientationsSupported": {
	},
	"msRRASVendorAttributeEntry": {
	},
	"interSiteTopologyGenerator": {
	},
	"options": {
	},
	"dnsRoot": {
	},
	"iPSECNegotiationPolicyType": {
	},
	"mS-SQL-InformationDirectory": {
	},
	"operatingSystemServicePack": {
	},
	"nextRid": {
	},
	"pekList": {
	},
	"subRefs": {
	},
	"oMTGuid": {
	},
	"pKTGuid": {
	},
	"company": {
	},
	"moniker": {
	},
	"comment": {
	},
	"ipPhone": {
	},
	"mS-DS-ConsistencyChildCount": {
	},
	"creator": {
	},
	"uNCName": {
	},
	"dBCSPwd": {
	},
	"mSMQDependentClientService": {
	},
	"certificateAuthorityObject": {
	},
	"ipsecID": {
	},
	"allowedAttributesEffective": {
	},
	"aCSMaxPeakBandwidthPerFlow": {
	},
	"Enabled": {
	},
	"perRecipDialogDisplayTable": {
	},
	"interSiteTopologyFailover": {
	},
	"transportAddressAttribute": {
	},
	"netbootCurrentClientCount": {
	},
	"rIDPreviousAllocationPool": {
	},
	"repsTo": {
	},
	"defaultSecurityDescriptor": {
	},
	"lastBackupRestorationTime": {
	},
	"fRSControlOutboundBacklog": {
	},
	"vendor": {
	},
	"gPLink": {
	},
	"originalDisplayTableMSDOS": {
	},
	"linkID": {
	},
	"msNPSavedCallingStationID": {
	},
	"mAPIID": {
	},
	"serviceBindingInformation": {
	},
	"nCName": {
	},
	"tokenGroupsNoGCAcceptable": {
	},
	"tokenGroupsGlobalAndUniversal": {
	},
	"msRASSavedFramedIPAddress": {
	},
	"aCSAllocableRSVPBandwidth": {
	},
	"lockOutObservationWindow": {
	},
	"netbootIntelliMirrorOSes": {
	},
	"aCSNonReservedMaxSDUSize": {
	},
	"notes": {
	},
	"retiredReplDSASignatures": {
	},
	"aCSMaxTokenBucketPerFlow": {
	},
	"addressEntryDisplayTable": {
	},
	"aCSMinimumDelayVariation": {
	},
	"fRSControlInboundBacklog": {
	},
	"flags": {
	},
	"mS-SQL-LastDiagnosticDate": {
	},
	"gPCMachineExtensionNames": {
	},
	"ms-DS-MachineAccountQuota": {
	},
	"perMsgDialogDisplayTable": {
	},
	"defaultLocalPolicyObject": {
	},
	"msRASSavedCallbackNumber": {
	},
	"parentCACertificateChain": {
	},
	"gPCFunctionalityVersion": {
	},
	"fRSServiceCommandStatus": {
	},
	"aCSNonReservedTokenSize": {
	},
	"aCSMaxSizeOfRSVPLogFile": {
	},
	"cost": {
	},
	"modifiedCountAtLastProm": {
	},
	"aCSRSVPLogFilesLocation": {
	},
	"supplementalCredentials": {
	},
	"bridgeheadTransportList": {
	},
	"mSMQSignCertificatesMig": {
	},
	"msRADIUSFramedIPAddress": {
	},
	"mS-DS-ReplicatesNCReason": {
	},
	"aCSEnableRSVPAccounting": {
	},
	"fRSTimeLastConfigChange": {
	},
	"printStaplingSupported": {
	},
	"interSiteTopologyRenew": {
	},
	"operatingSystemVersion": {
	},
	"otherLoginWorkstations": {
	},
	"netbootAllowNewClients": {
	},
	"mS-SQL-UnicodeSortOrder": {
	},
	"url": {
	},
	"pKT": {
	},
	"serviceInstanceVersion": {
	},
	"showInAdvancedViewOnly": {
	},
	"aCSMaxTokenRatePerFlow": {
	},
	"isCriticalSystemObject": {
	},
	"meetingMaxParticipants": {
	},
	"aNR": {
	},
	"rid": {
	},
	"proxyGenerationEnabled": {
	},
	"fRSControlDataCreation": {
	},
	"previousCACertificates": {
	},
	"contentIndexingAllowed": {
	},
	"policyReplicationFlags": {
	},
	"frsComputerReferenceBL": {
	},
	"aCSNonReservedPeakRate": {
	},
	"aCSMaxNoOfAccountFiles": {
	},
	"physicalLocationObject": {
	},
	"mSMQOutRoutingServers": {
	},
	"bridgeheadServerListBL": {
	},
	"msRADIUSCallbackNumber": {
	},
	"netbootMachineFilePath": {
	},
	"mSMQQueueJournalQuota": {
	},
	"netbootAnswerRequests": {
	},
	"operatingSystemHotfix": {
	},
	"attributeSecurityGUID": {
	},
	"superScopeDescription": {
	},
	"otherWellKnownObjects": {
	},
	"aCSNonReservedTxLimit": {
	},
	"authenticationOptions": {
	},
	"altSecurityIdentities": {
	},
	"gPCUserExtensionNames": {
	},
	"netbootInitialization": {
	},
	"mS-SQL-RegisteredOwner": {
	},
	"aCSMaxDurationPerFlow": {
	},
	"pKICriticalExtensions": {
	},
	"attributeDisplayNames": {
	},
	"mS-SQL-AllowImmediateUpdatingSubscription": {
	},
	"msRASSavedFramedRoute": {
	},
	"userSharedFolderOther": {
	},
	"extendedAttributeInfo": {
	},
	"netbootMirrorDataFile": {
	},
	"aCSMinimumPolicedSize": {
	},
	"localizationDisplayId": {
	},
	"meetingAdvertiseScope": {
	},
	"dSUIAdminNotification": {
	},
	"mS-SQL-LastUpdatedDate": {
	},
	"dSCorePropagationData": {
	},
	"implementedCategories": {
	},
	"defaultObjectCategory": {
	},
	"domainPolicyReference": {
	},
	"mSMQInRoutingServers": {
	},
	"printDuplexSupported": {
	},
	"pendingCACertificates": {
	},
	"nTSecurityDescriptor": {
	},
	"systemAuxiliaryClass": {
	},
	"aCSNonReservedTxSize": {
	},
	"mS-SQL-InformationURL": {
	},
	"replPropertyMetaData": {
	},
	"mS-SQL-PublicationURL": {
	},
	"printKeepPrintedJobs": {
	},
	"uSNDSALastObjRemoved": {
	},
	"dnsNotifySecondaries": {
	},
	"mS-DS-ConsistencyGuid": {
	},
	"frsComputerReference": {
	},
	"mS-SQL-ServiceAccount": {
	},
	"msNPCallingStationID": {
	},
	"mSMQSignCertificates": {
	},
	"ipsecOwnersReference": {
	},
	"builtinModifiedCount": {
	},
	"privilegeDisplayName": {
	},
	"dnsSecureSecondaries": {
	},
	"localizedDescription": {
	},
	"systemPossSuperiors": {
	},
	"displayNamePrintable": {
	},
	"servicePrincipalName": {
	},
	"pekKeyChangeInterval": {
	},
	"originalDisplayTable": {
	},
	"mS-SQL-LastBackupDate": {
	},
	"ipsecPolicyReference": {
	},
	"certificateTemplates": {
	},
	"hasPartialReplicaNCs": {
	},
	"localPolicyReference": {
	},
	"extendedCharsAllowed": {
	},
	"ipsecFilterReference": {
	},
	"ipsecISAKMPReference": {
	},
	"fRSMemberReferenceBL": {
	},
	"rpcNsTransferSyntax": {
	},
	"mSMQRoutingServices": {
	},
	"mS-SQL-MultiProtocol": {
	},
	"enrollmentProviders": {
	},
	"printNetworkAddress": {
	},
	"msRADIUSServiceType": {
	},
	"printPagesPerMinute": {
	},
	"printMediaSupported": {
	},
	"signatureAlgorithms": {
	},
	"fRSPartnerAuthLevel": {
	},
	"privilegeAttributes": {
	},
	"partialAttributeSet": {
	},
	"netbootLimitClients": {
	},
	"mS-SQL-ConnectionURL": {
	},
	"mS-SQL-AllowSnapshotFilesFTPDownloading": {
	},
	"pKIExpirationPeriod": {
	},
	"nonSecurityMemberBL": {
	},
	"initialAuthOutgoing": {
	},
	"msRADIUSFramedRoute": {
	},
	"controlAccessRights": {
	},
	//////////////////////////
	// SCHEMA: nis.schema
	"uidNumber": {
		Description: "An integer uniquely identifying a user in an administrative domain",
		Order:       9,
	},
	"gidNumber": {
		Description: "An integer uniquely identifying a group in an administrative domain",
		Order:       9,
	},
	"gecos": {
		Description: "The GECOS field; the common name",
	},
	"homeDirectory": {
		Description: "The absolute path to the home directory",
		Order:       6,
		Datalist: []string{
			"/home/",
			"/home/{user}",
		},
	},
	"loginShell": {
		Description: "The path to the login shell",
		Order:       6,
		Datalist: []string{
			"/bin/bash",
			"/bin/false",
			"/bin/sh",
		},
	},
	"shadowLastChange": {
	},
	"shadowMin": {
	},
	"shadowMax": {
	},
	"shadowWarning": {
	},
	"shadowInactive": {
	},
	"shadowExpire": {
	},
	"shadowFlag": {
	},
	"memberUid": {
	},
	"memberNisNetgroup": {
	},
	"nisNetgroupTriple": {
		Description: "Netgroup triple",
	},
	"ipServicePort": {
	},
	"ipServiceProtocol": {
	},
	"ipProtocolNumber": {
	},
	"oncRpcNumber": {
	},
	"ipHostNumber": {
		Description: "IP address",
	},
	"ipNetworkNumber": {
		Description: "IP network",
	},
	"ipNetmaskNumber": {
		Description: "IP netmask",
	},
	"macAddress": {
		Description: "MAC address",
	},
	"bootParameter": {
		Description: "Rpc.bootparamd parameter",
	},
	"bootFile": {
		Description: "Boot image name",
	},
	"nisMapName": {
	},
	"nisMapEntry": {
	},
	//////////////////////////
	// SCHEMA: openldap.schema
	//////////////////////////
	// SCHEMA: pmi.schema
	"role": {
		Description: "X.509 Role attribute, use ;binary",
	},
	"xmlPrivilegeInfo": {
		Description: "X.509 XML privilege information attribute",
	},
	"attributeCertificateAttribute": {
		Description: "X.509 Attribute certificate attribute, use ;binary",
	},
	"aACertificate": {
		Description: "X.509 AA certificate attribute, use ;binary",
	},
	"attributeDescriptorCertificate": {
		Description: "X.509 Attribute descriptor certificate attribute, use ;binary",
	},
	"attributeCertificateRevocationList": {
		Description: "X.509 Attribute certificate revocation list attribute, use ;binary",
	},
	"attributeAuthorityRevocationList": {
		Description: "X.509 AA certificate revocation list attribute, use ;binary",
	},
	"delegationPath": {
		Description: "X.509 Delegation path attribute, use ;binary",
	},
	"privPolicy": {
		Description: "X.509 Privilege policy attribute, use ;binary",
	},
	"protPrivPolicy": {
		Description: "X.509 Protected privilege policy attribute, use ;binary",
	},
	"xmlPrivPolicy": {
		Description: "X.509 XML Protected privilege policy attribute",
	},
	//////////////////////////
	// SCHEMA: ppolicy.schema
	"pwdAttribute": {
		Description: "Name of the attribute to which the password policy is applied. For example, the password policy may be applied to the userPassword attribute",
	},
	"pwdMinAge": {
		Description: "Number of seconds that must elapse between modifications to the password. If this attribute is not present, 0 seconds is assumed.",
	},
	"pwdMaxAge": {
		Description: "Number of seconds after which a modified password will expire. If this attribute is not present, or if the value is 0 the password does not expire. If not 0, the value must be greater than or equal to the value of the pwdMinAge.",
	},
	"pwdInHistory": {
		Description: "Maximum number of used passwords stored in the pwdHistory attribute. If this attribute is not present, or if the value is 0, used passwords are not stored in the pwdHistory attribute and thus may be reused.",
	},
	"pwdCheckQuality": {
		Description: "Indicates how the password quality will be verified while being modified or added",
	},
	"pwdMinLength": {
		Description: "When quality checking is enabled, this attribute holds the minimum number of characters that must be used in a password. If this attribute is not present, no minimum password length will be enforced. If the server is unable to check the length (due to a hashed password or otherwise), the server will, depending on the value of the pwdCheckQuality attribute, either accept the password without checking it ('0' or '1') or refuse it ('2').",
	},
	"pwdExpireWarning": {
		Description: "specifies the maximum number of seconds before a password is due to expire that expiration warning messages will be returned to an authenticating user. If this attribute is not present, or if the value is 0 no warnings will be returned. If not 0, the value must be smaller than the value of the pwdMaxAge attribute.",
	},
	"pwdGraceAuthNLimit": {
		Description: "This attribute specifies the number of times an expired password can be used to authenticate. If this attribute is not present or if the value is 0, authentication will fail.",
	},
	"pwdLockout": {
		Description: "This attribute indicates, when its value is \"TRUE\", that the password may not be used to authenticate after a specified number of consecutive failed bind attempts. The maximum number of consecutive failed bind attempts is specified in pwdMaxFailure. If this attribute is not present, or if the value is \"FALSE\", the password may be used to authenticate when the number of failed bind attempts has been reached.",
	},
	"pwdLockoutDuration": {
		Description: "This attribute holds the number of seconds that the password cannot be used to authenticate due to too many failed bind attempts. If this attribute is not present, or if the value is 0 the password cannot be used to authenticate until reset by a password administrator.",
	},
	"pwdMaxFailure": {
		Description: "This attribute specifies the number of consecutive failed bind attempts after which the password may not be used to authenticate. If this attribute is not present, or if the value is 0, this policy is not checked, and the value of pwdLockout will be ignored.",
	},
	"pwdFailureCountInterval": {
		Description: "This attribute holds the number of seconds after which the password failures are purged from the failure counter, even though no successful authentication occurred. If this attribute is not present, or if its value is 0, the failure counter is only reset by a successful authentication.",
	},
	"pwdMustChange": {
		Description: "This attribute specifies with a value of \"TRUE\" that users must change their passwords when they first bind to the directory after a password is set or reset by a password administrator. If this attribute is not present, or if the value is \"FALSE\", users are not required to change their password upon binding after the password administrator sets or resets the password. This attribute is not set due to any actions specified by this document, it is typically set by a password administrator after resetting a user's password.",
	},
	"pwdAllowUserChange": {
		Description: "This attribute indicates whether users can change their own passwords, although the change operation is still subject to access control. If this attribute is not present, a value of \"TRUE\" is assumed. This attribute is intended to be used in the absence of an access control mechanism.",
	},
	"pwdSafeModify": {
		Description: "This attribute specifies whether or not the existing password must be sent along with the new password when being changed. If this attribute is not present, a \"FALSE\" value is assumed.",
	},
	"pwdMaxRecordedFailure": {
		Description: "This attribute specifies the maximum number of consecutive failed bind attempts to record. If this attribute is not present, or if the value is 0, it defaults to the value of pwdMaxFailure. If that value is also 0, this value defaults to 5.",
	},
	"pwdCheckModule": {
		Description: "Loadable module that instantiates check_password() function. This attribute names a user-defined loadable module that provides a check_password() function. If pwdCheckQuality is set to '1' or '2' this function will be called after all of the internal password quality checks have been passed. The function has this prototype: int check_password( char *password, char **errormessage, void *arg ) The function should return LDAP_SUCCESS for a valid password.",
	},
}
