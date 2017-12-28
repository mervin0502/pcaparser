package pcaparser

type Http struct {
	Data []byte
}

//ParseHttp
func ParseHttp(data []byte) (*Http, error) {
	http := &Http{}
	http.Data = data
	// glog.V(2).Infof("f[%d %x %s", len(data), data, string(data))
	return http, nil
}
