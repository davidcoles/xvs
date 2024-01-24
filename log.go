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

type Nil struct{}

func (n *Nil) Println(...any)         {}
func (n *Nil) EMERG(string, ...any)   {}
func (n *Nil) ALERT(string, ...any)   {}
func (n *Nil) CRIT(string, ...any)    {}
func (n *Nil) ERR(string, ...any)     {}
func (n *Nil) WARNING(string, ...any) {}
func (n *Nil) NOTICE(string, ...any)  {}
func (n *Nil) INFO(string, ...any)    {}
func (n *Nil) DEBUG(string, ...any)   {}
