package vulns

import (
	"math"
	"strings"
)

// CVSS3 computes the CVSS v3.0/v3.1 base score of a vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". ok is false when the
// vector is not a complete v3 base vector.
func CVSS3(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, w := range weights {
		x, ok := w[m[k]]
		if !ok {
			return 0, false
		}
		val[k] = x
	}
	changed := m["S"] == "C"
	if !changed && m["S"] != "U" {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	prv, ok := pr[m["PR"]]
	if !ok {
		return 0, false
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * val["AV"] * val["AC"] * prv * val["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// roundUp is the CVSS v3.1 rounding function.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// ScoreSeverity maps a CVSS score to a severity name.
func ScoreSeverity(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	}
	return "low"
}
