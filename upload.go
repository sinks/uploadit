package main

import (
	"github.com/twinj/uuid"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type Upload struct {
	Files []string
	Id    uuid.Uuid
}

func (u *Upload) Handle(w http.ResponseWriter, req *http.Request) error {
	reader, err := req.MultipartReader()
	if err != nil {
		return err
	}
	u.Id = uuid.NewV1()
	part, err := reader.NextPart()
	for err == nil {
		err = u.HandlePart(part)
		part, err = reader.NextPart()
	}
	if err == io.EOF {
		return nil
	}
	return err
}

func (u *Upload) dir() string {
	return filepath.Join(u.Id.String())
}

func (u *Upload) path(fileName string) string {
	return filepath.Join(u.dir(), fileName)
}

func (u *Upload) createFileDir() error {
	err := os.MkdirAll(u.dir(), os.ModePerm)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

func (u *Upload) HandlePart(part *multipart.Part) error {
	err := u.createFileDir()
	if err != nil {
		return err
	}
	openFile, err := os.Create(u.path(part.FileName()))
	if err != nil {
		return err
	}
	defer openFile.Close()

	_, err = io.Copy(openFile, part)
	if err != nil {
		return err
	}
	u.Files = append(u.Files, part.FileName())
	return nil
}
