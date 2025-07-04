package main

import (
	"fmt"
	"testjunior"
	"testjunior/internal/handler"
	"testjunior/internal/repository"
	"testjunior/internal/service"

	_ "github.com/lib/pq"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/subosito/gotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	fmt.Println("Start server...")
	logrus.SetFormatter(new(logrus.JSONFormatter))

	if err := gotenv.Load(); err != nil {
		logrus.Fatalf("Error loading env: %s", err.Error())
	}

	if err := InitConfig(); err != nil {
		logrus.Fatalf("Error loading config: %s", err.Error())
	}
	db, err := repository.NewPostgresDB(repository.Config{
		Host:     viper.GetString("db.host"),
		Port:     viper.GetString("db.port"),
		Username: viper.GetString("db.username"),
		DBName:   viper.GetString("db.dbname"),
		SSLMode:  viper.GetString("db.sslmode"),
		Password: viper.GetString("db.password"),
	})
	if err != nil {
		logrus.Fatalf("failed to initialize db: %s", err.Error())
	}

	repos := repository.NewRepository(db)
	services := service.NewService(repos)
	handlers := handler.NewHandler(services)

	srv := new(testjunior.Server)

	h := handlers.InitRoutes()
	h.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	if err := srv.Run(viper.GetString("port"), h); err != nil {
		logrus.Fatalf("error occured while running http server: %s", err.Error())
	}
}

func InitConfig() error {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	return viper.ReadInConfig()
}
