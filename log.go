package xvs

type Log interface {
	Println(...any)
	EMERG(string, ...interface{})
	ALERT(string, ...interface{})
	CRIT(string, ...interface{})
	ERR(string, ...interface{})
	WARNING(string, ...interface{})
	NOTICE(string, ...interface{})
	INFO(string, ...interface{})
	DEBUG(string, ...interface{})
}

type nul struct{}

func (n *nul) Println(...any)         {}
func (n *nul) EMERG(string, ...any)   {}
func (n *nul) ALERT(string, ...any)   {}
func (n *nul) CRIT(string, ...any)    {}
func (n *nul) ERR(string, ...any)     {}
func (n *nul) WARNING(string, ...any) {}
func (n *nul) NOTICE(string, ...any)  {}
func (n *nul) INFO(string, ...any)    {}
func (n *nul) DEBUG(string, ...any)   {}
