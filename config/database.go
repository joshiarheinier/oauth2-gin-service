package config

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
)

var (
	engine = &xorm.Engine{}
	errFailedToConnectToSQL = "Failed to connect to mysql %v\n"
)

func init() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&parseTime=true",
		"root", "asdasdasd", "localhost", "new_schema")
	var err error
	engine, err = xorm.NewEngine("mysql", dsn)
	if err != nil {
		err = fmt.Errorf(errFailedToConnectToSQL, err)
		panic(err.Error())
	}
	engine.SetConnMaxLifetime(-1)

	//this will be sync the struct into the table and the table will be same with struct
	engine.Sync()
}

func NewDBEngine() *xorm.Engine {
	return engine
}