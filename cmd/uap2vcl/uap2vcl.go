package main

import (
	"flag"
	"fmt"
	"log"
	stdos "os"
	"strings"
	"text/template"

	"github.com/ua-parser/uap-go/uaparser"
)

func main() {
	var p string
	var pvcl bool

	flag.StringVar(&p, "regex", "./regexes.yaml", "uap definition file")
	flag.BoolVar(&pvcl, "pure-vcl", false, "generate VCL that doesn't rely on vmods (Varnish Cache compatible, but slower)")
	flag.Parse()

	parser, err := uaparser.New(p)
	if err != nil {
		log.Fatal(err)
	}

	quoteExpr := func(str string, f string) string {
		if f != "" && f != "i" {
			panic(fmt.Errorf("unknown regex_flag: %s", f));
		} else if f == "i" {
			str = "(?i)" + str
		}
		str = strings.Replace(str, `"`, `\"`, -1)

		if pvcl {
			return `{"(?:.*?)(?:`+ str +`).*"}`
		} else {
			return `"(?:.*?)(?:`+ str +`).*"`
		}
	}

	quoteSub := func(str string) string {
		str = strings.Replace(strings.Replace(str, "$", "\\", -1), "\"", "\\\"", -1)
		if pvcl {
			return `{"` + str + `"}`
		} else {
			return `"` + str + `"`
		}
	}

	// for each type, sanitize and add a catch-all case
	ua := *parser.RegexesDefinitions.UA[0]
	ua.Expr = ""
	ua.FamilyReplacement = "Other"
	ua.V1Replacement = ""
	ua.V2Replacement = ""
	ua.V3Replacement = ""
	parser.RegexesDefinitions.UA = append(parser.RegexesDefinitions.UA, &ua)
	for i, ua := range parser.RegexesDefinitions.UA {
		parser.RegexesDefinitions.UA[i].Expr = quoteExpr(ua.Expr, ua.Flags)
		parser.RegexesDefinitions.UA[i].FamilyReplacement = quoteSub(ua.FamilyReplacement)
		parser.RegexesDefinitions.UA[i].V1Replacement = quoteSub(ua.V1Replacement)
		parser.RegexesDefinitions.UA[i].V2Replacement = quoteSub(ua.V2Replacement)
		parser.RegexesDefinitions.UA[i].V3Replacement = quoteSub(ua.V3Replacement)
	}

	os := *parser.RegexesDefinitions.OS[0]
	os.Expr = ""
	os.OSReplacement = "Other"
	os.V1Replacement = ""
	os.V2Replacement = ""
	os.V3Replacement = ""
	os.V4Replacement = ""
	parser.RegexesDefinitions.OS = append(parser.RegexesDefinitions.OS, &os)
	for i, os := range parser.RegexesDefinitions.OS {
		parser.RegexesDefinitions.OS[i].Expr = quoteExpr(os.Expr, os.Flags)
		parser.RegexesDefinitions.OS[i].OSReplacement = quoteSub(os.OSReplacement)
		parser.RegexesDefinitions.OS[i].V1Replacement = quoteSub(os.V1Replacement)
		parser.RegexesDefinitions.OS[i].V2Replacement = quoteSub(os.V2Replacement)
		parser.RegexesDefinitions.OS[i].V3Replacement = quoteSub(os.V3Replacement)
		parser.RegexesDefinitions.OS[i].V4Replacement = quoteSub(os.V4Replacement)
	}

	device := *parser.RegexesDefinitions.Device[0]
	device.Expr = ""
	device.DeviceReplacement = "Other"
	device.BrandReplacement = ""
	device.ModelReplacement = ""
	parser.RegexesDefinitions.Device = append(parser.RegexesDefinitions.Device, &device)
	for i, device := range parser.RegexesDefinitions.Device {
		parser.RegexesDefinitions.Device[i].Expr = quoteExpr(device.Expr, device.Flags)
		parser.RegexesDefinitions.Device[i].DeviceReplacement = quoteSub(device.DeviceReplacement)
		parser.RegexesDefinitions.Device[i].BrandReplacement = quoteSub(device.BrandReplacement)
		parser.RegexesDefinitions.Device[i].ModelReplacement = quoteSub(device.ModelReplacement)
	}

	var tmplString string
	if pvcl {
		tmplString = cache_tmpl
	} else {
		tmplString = enterprise_tmpl
	}
	tmpl, err := template.New("test").Parse(tmplString)

	if err != nil { panic(err) }
	err = tmpl.Execute(stdos.Stdout, &parser.RegexesDefinitions)
	if err != nil { panic(err) }
}

const cache_tmpl = `vcl 4.1;
import std;
sub uap_detect_ua {
	{{- range $i, $el := .UA }}
	{{ if (ne $i 0) -}} else {{- end}} if (req.http.user-agent ~ {{ .Expr }}) {
		set req.http.expr = {{ .Expr }};
		set req.http.ua-family = regsuball(req.http.user-agent, {{ .Expr }}, {{ .FamilyReplacement }});
		set req.http.ua-major = regsub(req.http.user-agent, {{ .Expr }}, {{ .V1Replacement }});
		set req.http.ua-minor = regsub(req.http.user-agent, {{ .Expr }}, {{ .V2Replacement }});
		set req.http.ua-patch = regsub(req.http.user-agent, {{ .Expr }}, {{ .V3Replacement }});
	}
	{{- end }}
}

sub uap_detect_os {
	{{- range $i, $el := .OS }}
	{{ if (ne $i 0) -}} else {{- end}} if (req.http.user-agent ~ {{ .Expr }}) {
		set req.http.os-family = regsub(req.http.user-agent, {{ .Expr }}, {{ .OSReplacement }});
		set req.http.os-major = regsub(req.http.user-agent, {{ .Expr }}, {{ .V1Replacement }});
		set req.http.os-minor = regsub(req.http.user-agent, {{ .Expr }}, {{ .V2Replacement }});
		set req.http.os-patch = regsub(req.http.user-agent, {{ .Expr }}, {{ .V3Replacement }});
		set req.http.os-patch_minor = regsub(req.http.user-agent, {{ .Expr }}, {{ .V4Replacement }});
	}
	{{- end }}
}
sub uap_detect_device {
	{{- range $i, $el := .Device }}
	{{ if (ne $i 0) -}} else {{- end}} if (req.http.user-agent ~ {{ .Expr }}) {
		set req.http.device-family = regsub(req.http.user-agent, {{ .Expr }}, {{ .DeviceReplacement }});
		set req.http.device-brand = regsub(req.http.user-agent, {{ .Expr }}, {{ .BrandReplacement }});
		set req.http.device-model = regsub(req.http.user-agent, {{ .Expr }}, {{ .ModelReplacement }});
	}
	{{- end }}
}

sub uap_detect {
	call uap_detect_ua;
	call uap_detect_os;
	call uap_detect_device;
}

sub vcl_synth {
	if (false) { call uap_detect; }
}
`

const enterprise_tmpl = `vcl 4.1;
import rewrite;

sub vcl_init {
	new uap_ua_rs = rewrite.ruleset(string = """
		{{- range $_, $el := .UA }}
		{{ .Expr }} {{ .FamilyReplacement }} {{ .V1Replacement }} {{ .V2Replacement }} {{ .V3Replacement }}
	{{- end }}
	""");
	new uap_os_rs = rewrite.ruleset(string = """
		{{- range $_, $el := .OS }}
		{{ .Expr }} {{ .OSReplacement }} {{ .V1Replacement }} {{ .V2Replacement }} {{ .V3Replacement }} {{ .V4Replacement }}
	{{- end }}
	""");
	new uap_device_rs = rewrite.ruleset(string = """
		{{- range $_, $el := .Device }}
		{{ .Expr }} {{ .DeviceReplacement }} {{ .BrandReplacement }} {{ .ModelReplacement }}
	{{- end }}
	""");
}

sub uap_detect {
	uap_ua_rs.match(req.http.user-agent);
	set req.http.ua-family = uap_ua_rs.rewrite(2, only_matching);
	set req.http.ua-major = uap_ua_rs.rewrite(3, only_matching);
	set req.http.ua-minor = uap_ua_rs.rewrite(4, only_matching);
	set req.http.ua-patch = uap_ua_rs.rewrite(5, only_matching);

	uap_os_rs.match(req.http.user-agent);
	set req.http.os-family = uap_os_rs.rewrite(2, only_matching);
	set req.http.os-major = uap_os_rs.rewrite(3, only_matching);
	set req.http.os-minor = uap_os_rs.rewrite(4, only_matching);
	set req.http.os-patch = uap_os_rs.rewrite(5, only_matching);
	set req.http.os-patch_minor = uap_os_rs.rewrite(6, only_matching);

	uap_device_rs.match(req.http.user-agent);
	set req.http.device-family = uap_device_rs.rewrite(2, only_matching);
	set req.http.device-brand = uap_device_rs.rewrite(3, only_matching);
	set req.http.device-model = uap_device_rs.rewrite(4, only_matching);
}

sub vcl_synth {
	if (false) { call uap_detect; }
}
`
