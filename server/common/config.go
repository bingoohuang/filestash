package common

import (
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

var (
	Config     Configuration
	configPath = filepath.Join(GetCurrentDir(), ConfigPath+"config.json")
)

type Configuration struct {
	onChange       []ChangeListener
	mu             sync.Mutex
	currentElement *FormElement
	cache          KeyValueStore
	form           []Form
	Conn           []map[string]interface{}
}

type Form struct {
	Title  string
	Form   []Form
	Elmnts []FormElement
}

type FormElement struct {
	Id          string      `json:"id,omitempty"`
	Name        string      `json:"label"`
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Placeholder string      `json:"placeholder,omitempty"`
	Opts        []string    `json:"options,omitempty"`
	Target      []string    `json:"target,omitempty"`
	ReadOnly    bool        `json:"readonly"`
	Default     interface{} `json:"default"`
	Value       interface{} `json:"value"`
	MultiValue  bool        `json:"multi,omitempty"`
	Datalist    []string    `json:"datalist,omitempty"`
	Order       int         `json:"-"`
	Required    bool        `json:"required"`
}

func init() {
	Config = NewConfiguration()
	Config.Load()
	Config.Save()
	Config.Initialise()
}

func NewConfiguration() Configuration {
	return Configuration{
		onChange: make([]ChangeListener, 0),
		mu:       sync.Mutex{},
		cache:    NewKeyValueStore(),
		form: []Form{
			{
				Title: "general",
				Elmnts: []FormElement{
					{Name: "name", Type: "text", Default: "Filestash", Description: "Name has shown in the UI", Placeholder: "Default: \"Filestash\""},
					{Name: "port", Type: "number", Default: 8334, Description: "Port on which the application is available.", Placeholder: "Default: 8334"},
					{Name: "host", Type: "text", Description: "The host people need to use to access this server", Placeholder: "Eg: \"demo.filestash.app\""},
					{Name: "secret_key", Type: "password", Description: "The key that's used to encrypt and decrypt content. Update this settings will invalidate existing user sessions and shared links, use with caution!"},
					{Name: "force_ssl", Type: "boolean", Description: "Enable the web security mechanism called 'Strict Transport Security'"},
					{Name: "editor", Type: "select", Default: "emacs", Opts: []string{"base", "emacs", "vim"}, Description: "Keybinding to be use in the editor. Default: \"emacs\""},
					{Name: "fork_button", Type: "boolean", Default: true, Description: "Display the fork button in the login screen"},
					{Name: "logout", Type: "select", Default: "default", Opts: []string{"default", "hide", "referrer"}, Description: "Behaviour of the logout button. By default it redirects to the login page but can also be hidden or redirect to the referrer URL"},
					{Name: "display_hidden", Type: "boolean", Default: false, Description: "Should files starting with a dot be visible by default?"},
					{Name: "auto_connect", Type: "boolean", Default: false, Description: "User don't have to click on the login button if an admin is prefilling a unique backend"},
					{Name: "remember_me", Type: "boolean", Default: true, Description: "Visiblity of the remember me button on the login screen"},
					{Name: "upload_button", Type: "boolean", Default: false, Description: "Display the upload button on any device"},
					{Name: "custom_css", Type: "long_text", Default: "", Description: "Set custom css code for your instance"},
				},
			},
			{
				Title: "features",
				Form: []Form{
					{
						Title: "share",
						Elmnts: []FormElement{
							{Name: "enable", Type: "boolean", Default: true, Description: "Enable/Disable the share feature"},
						},
					},
				},
			},
			{
				Title: "log",
				Elmnts: []FormElement{
					{Name: "enable", Type: "enable", Target: []string{"log_level"}, Default: true},
					{Name: "level", Type: "select", Default: "INFO", Opts: []string{"DEBUG", "INFO", "WARNING", "ERROR"}, Id: "log_level", Description: "Default: \"INFO\". This setting determines the level of detail at which log events are written to the log file"},
					{Name: "telemetry", Type: "boolean", Default: false, Description: "We won't share anything with any third party. This will only to be used to improve Filestash"},
				},
			},
			{
				Title: "email",
				Elmnts: []FormElement{
					{Name: "server", Type: "text", Default: "smtp.gmail.com", Description: "Address of the SMTP email server.", Placeholder: "Default: smtp.gmail.com"},
					{Name: "port", Type: "number", Default: 587, Description: "Port of the SMTP email server. Eg: 587", Placeholder: "Default: 587"},
					{Name: "username", Type: "text", Description: "The username for authenticating to the SMTP server.", Placeholder: "Eg: username@gmail.com"},
					{Name: "password", Type: "password", Description: "The password associated with the SMTP username.", Placeholder: "Eg: Your google password"},
					{Name: "from", Type: "text", Description: "Email address visible on sent messages.", Placeholder: "Eg: username@gmail.com"},
				},
			},
			{
				Title: "auth",
				Elmnts: []FormElement{
					{Name: "admin", Type: "bcrypt", Default: "", Description: "Password of the admin section."},
				},
			},
		},
		Conn: make([]map[string]interface{}, 0),
	}
}

func (f Form) MarshalJSON() ([]byte, error) {
	return []byte(f.toJSON(func(el FormElement) string {
		a, e := json.Marshal(el)
		if e != nil {
			return ""
		}
		return string(a)
	})), nil
}

func (f Form) toJSON(fn func(el FormElement) string) string {
	formatKey := func(str string) string {
		return strings.Replace(str, " ", "_", -1)
	}
	ret := ""
	if f.Title != "" {
		ret = fmt.Sprintf("%s\"%s\":", ret, formatKey(f.Title))
	}
	for i := 0; i < len(f.Elmnts); i++ {
		if i == 0 {
			ret = fmt.Sprintf("%s{", ret)
		}
		ret = fmt.Sprintf("%s\"%s\":%s", ret, formatKey(f.Elmnts[i].Name), fn(f.Elmnts[i]))
		if i == len(f.Elmnts)-1 && len(f.Form) == 0 {
			ret = fmt.Sprintf("%s}", ret)
		}
		if i != len(f.Elmnts)-1 || len(f.Form) != 0 {
			ret = fmt.Sprintf("%s,", ret)
		}
	}

	for i := 0; i < len(f.Form); i++ {
		if i == 0 && len(f.Elmnts) == 0 {
			ret = fmt.Sprintf("%s{", ret)
		}
		ret = ret + f.Form[i].toJSON(fn)
		if i == len(f.Form)-1 {
			ret = fmt.Sprintf("%s}", ret)
		}
		if i != len(f.Form)-1 {
			ret = fmt.Sprintf("%s,", ret)
		}
	}

	if len(f.Form) == 0 && len(f.Elmnts) == 0 {
		ret = fmt.Sprintf("%s{}", ret)
	}

	return ret
}

type FormIterator struct {
	Path string
	*FormElement
}

func (f *Form) Iterator() []FormIterator {
	slice := make([]FormIterator, 0)

	for i := range f.Elmnts {
		slice = append(slice, FormIterator{
			strings.ToLower(f.Title),
			&f.Elmnts[i],
		})
	}
	for _, node := range f.Form {
		r := node.Iterator()
		if f.Title != "" {
			for i := range r {
				r[i].Path = strings.ToLower(f.Title) + "." + r[i].Path
			}
		}
		slice = append(r, slice...)
	}
	return slice
}

func (c *Configuration) Load() {
	file, err := os.OpenFile(configPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		Log.Warning("Can't read from config file")
		return
	}
	defer file.Close()

	cFile, err := ioutil.ReadAll(file)
	if err != nil {
		Log.Warning("Can't parse config file")
		return
	}

	// Extract enabled backends
	c.Conn = func(cFile []byte) []map[string]interface{} {
		var d struct {
			Connections []map[string]interface{} `json:"connections"`
		}
		json.Unmarshal(cFile, &d)
		return d.Connections
	}(cFile)

	// Hydrate Config with data coming from the config file
	d := JsonIterator(string(cFile))
	for i := range d {
		c = c.Get(d[i].Path)
		if c.Interface() != d[i].Value {
			c.currentElement.Value = d[i].Value
		}
	}
	c.cache.Clear()

	Log.SetVisibility(c.Get("log.level").String())

	go func() { // Trigger all the event listeners
		for i := 0; i < len(c.onChange); i++ {
			c.onChange[i].Listener <- nil
		}
	}()
	return
}

type JSONIterator struct {
	Path  string
	Value interface{}
}

func JsonIterator(json string) []JSONIterator {
	j := make([]JSONIterator, 0)

	var recurJSON func(res gjson.Result, pkey string)
	recurJSON = func(res gjson.Result, pkey string) {
		if pkey != "" {
			pkey = pkey + "."
		}
		res.ForEach(func(key, value gjson.Result) bool {
			k := pkey + key.String()
			if value.IsObject() {
				recurJSON(value, k)
				return true
			} else if value.IsArray() {
				return true
			}
			j = append(j, JSONIterator{k, value.Value()})
			return true
		})
	}

	recurJSON(gjson.Parse(json), "")
	return j
}

func (c *Configuration) Debug() *FormElement {
	return c.currentElement
}

func (c *Configuration) Initialise() {
	if env := os.Getenv("ADMIN_PASSWORD"); env != "" {
		c.Get("auth.admin").Set(env)
	}
	if env := os.Getenv("APPLICATION_URL"); env != "" {
		c.Get("general.host").Set(env).String()
	}
	if c.Get("general.secret_key").String() == "" {
		key := RandomString(16)
		c.Get("general.secret_key").Set(key)
	}

	if len(c.Conn) == 0 {
		c.Conn = []map[string]interface{}{
			{
				"type":  "webdav",
				"label": "WebDav",
			},
			{
				"type":  "ftp",
				"label": "FTP",
			},
			{
				"type":  "sftp",
				"label": "SFTP",
			},
			{
				"type":  "git",
				"label": "GIT",
			},
			{
				"type":  "s3",
				"label": "S3",
			},
			{
				"type":  "dropbox",
				"label": "Dropbox",
			},
			{
				"type":  "gdrive",
				"label": "Drive",
			},
		}
		c.Save()
	}
	InitSecretDerivate(c.Get("general.secret_key").String())
}

func (c *Configuration) Save() *Configuration {
	// convert config data to an appropriate json struct
	form := append(c.form, Form{Title: "connections"})
	v := Form{Form: form}.toJSON(func(el FormElement) string {
		a, e := json.Marshal(el.Value)
		if e != nil {
			return "null"
		}
		return string(a)
	})
	v, _ = sjson.Set(v, "connections", c.Conn)

	// deploy the config in our config.json
	file, err := os.Create(configPath)
	if err != nil {
		Log.Error("Filestash needs to be able to create/edit its own configuration which it can't at the moment. Change the permission for filestash to create and edit `%s`", configPath)
		return c
	}
	defer file.Close()
	file.Write(PrettyPrint([]byte(v)))
	return c
}

func (c *Configuration) Export() interface{} {
	return struct {
		Editor        string            `json:"editor"`
		ForkButton    bool              `json:"fork_button"`
		DisplayHidden bool              `json:"display_hidden"`
		AutoConnect   bool              `json:"auto_connect"`
		Name          string            `json:"name"`
		RememberMe    bool              `json:"remember_me"`
		UploadButton  bool              `json:"upload_button"`
		Connections   interface{}       `json:"connections"`
		EnableShare   bool              `json:"enable_share"`
		Logout        string            `json:"logout"`
		MimeTypes     map[string]string `json:"mime"`
	}{
		Editor:        c.Get("general.editor").String(),
		ForkButton:    c.Get("general.fork_button").Bool(),
		DisplayHidden: c.Get("general.display_hidden").Bool(),
		AutoConnect:   c.Get("general.auto_connect").Bool(),
		Name:          c.Get("general.name").String(),
		RememberMe:    c.Get("general.remember_me").Bool(),
		UploadButton:  c.Get("general.upload_button").Bool(),
		Connections:   c.Conn,
		EnableShare:   c.Get("features.share.enable").Bool(),
		Logout:        c.Get("general.logout").String(),
		MimeTypes:     AllMimeTypes(),
	}
}

func (c *Configuration) Get(key string) *Configuration {
	var traverse func(forms *[]Form, path []string) *FormElement
	traverse = func(forms *[]Form, path []string) *FormElement {
		if len(path) == 0 {
			return nil
		}
		for i := range *forms {
			currentForm := (*forms)[i]
			if currentForm.Title == path[0] {
				if len(path) == 2 {
					// we are on a leaf
					// 1) attempt to get a `formElement`
					for j, el := range currentForm.Elmnts {
						if el.Name == path[1] {
							return &(*forms)[i].Elmnts[j]
						}
					}
					// 2) `formElement` does not exist, let's create it
					(*forms)[i].Elmnts = append(currentForm.Elmnts, FormElement{Name: path[1], Type: "text"})
					return &(*forms)[i].Elmnts[len(currentForm.Elmnts)]
				} else {
					// we are NOT on a leaf, let's continue our tree transversal
					return traverse(&(*forms)[i].Form, path[1:])
				}
			}
		}
		// append a new `form` if the current key doesn't exist
		*forms = append(*forms, Form{Title: path[0]})
		return traverse(forms, path)
	}

	// increase speed (x4 with our bench) by using a cache
	c.mu.Lock()
	tmp := c.cache.Get(key)
	if tmp == nil {
		c.currentElement = traverse(&c.form, strings.Split(key, "."))
		c.cache.Set(key, c.currentElement)
	} else {
		c.currentElement = tmp.(*FormElement)
	}
	c.mu.Unlock()
	return c
}

func (c *Configuration) Schema(fn func(*FormElement) *FormElement) *Configuration {
	fn(c.currentElement)
	c.cache.Clear()
	return c
}

func (c *Configuration) Default(value interface{}) *Configuration {
	if c.currentElement == nil {
		return c
	}

	c.mu.Lock()
	if c.currentElement.Default == nil {
		c.currentElement.Default = value
		c.Save()
	} else {
		if c.currentElement.Default != value {
			Log.Debug("Attempt to set multiple default config value => %+v", c.currentElement)
		}
	}
	c.mu.Unlock()
	return c
}

func (c *Configuration) Set(value interface{}) *Configuration {
	if c.currentElement == nil {
		return c
	}

	c.mu.Lock()
	c.cache.Clear()
	if c.currentElement.Value != value {
		c.currentElement.Value = value
		c.Save()
	}
	c.mu.Unlock()
	return c
}

func (c *Configuration) String() string {
	val := c.Interface()
	switch val.(type) {
	case string:
		return val.(string)
	case []byte:
		return string(val.([]byte))
	}
	return ""
}

func (c *Configuration) Int() int {
	val := c.Interface()
	switch val.(type) {
	case float64:
		return int(val.(float64))
	case int64:
		return int(val.(int64))
	case int:
		return val.(int)
	}
	return 0
}

func (c *Configuration) Bool() bool {
	val := c.Interface()
	switch val.(type) {
	case bool:
		return val.(bool)
	}
	return false
}

func (c *Configuration) Interface() interface{} {
	if c.currentElement == nil {
		return nil
	}
	val := c.currentElement.Value
	if val == nil {
		val = c.currentElement.Default
	}
	return val
}

func (c *Configuration) MarshalJSON() ([]byte, error) {
	form := c.form
	form = append(form, Form{
		Title: "constant",
		Elmnts: []FormElement{
			{Name: "user", Type: "boolean", ReadOnly: true, Value: func() string {
				if u, err := user.Current(); err == nil {
					if u.Username != "" {
						return u.Username
					}
					return u.Name
				}
				return "n/a"
			}()},
			{Name: "emacs", Type: "boolean", ReadOnly: true, Value: func() bool {
				if _, err := exec.LookPath("emacs"); err == nil {
					return true
				}
				return false
			}()},
			{Name: "pdftotext", Type: "boolean", ReadOnly: true, Value: func() bool {
				if _, err := exec.LookPath("pdftotext"); err == nil {
					return true
				}
				return false
			}()},
		},
	})
	return Form{
		Form: form,
	}.MarshalJSON()
}

func (c *Configuration) ListenForChange() ChangeListener {
	c.mu.Lock()
	change := ChangeListener{
		Id:       QuickString(20),
		Listener: make(chan interface{}, 0),
	}
	c.onChange = append(c.onChange, change)
	c.mu.Unlock()
	return change
}

func (c *Configuration) UnlistenForChange(l ChangeListener) {
	c.mu.Lock()
	for i := 0; i < len(c.onChange); i++ {
		if c.onChange[i].Id == l.Id {
			if len(c.onChange)-1 >= 0 {
				close(c.onChange[i].Listener)
				c.onChange[i] = c.onChange[len(c.onChange)-1]
				c.onChange = c.onChange[:len(c.onChange)-1]
			}
			break
		}
	}
	c.mu.Unlock()
}

type ChangeListener struct {
	Id       string
	Listener chan interface{}
}
