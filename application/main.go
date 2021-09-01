package main

import (
	"bufio"
	"fmt"
	"log"
	"main/encryptor"
	"main/user"
	"os"
	"os/exec"
	"strings"

	"github.com/chzyer/readline"
)

func main() {

	reader := bufio.NewReader(os.Stdin)

	listUsers := []user.User{}

	for {

		option := menu()

		switch option {
		case "1":

			fmt.Println("Ingresa el nombre del nuevo usuario: ")
			userName, _ := reader.ReadString('\n')

			priv, pub := encryptor.GenerateRsaKeyPair()

			myuser := user.User{
				Name:       userName,
				PrivateKey: priv,
				PublicKey:  pub,
			}
			listUsers = append(listUsers, myuser)
			fmt.Printf("Par de llaves generado para el usuario %s\n", myuser.Name)
			pressKeyToContinue()
		case "2":
			fmt.Println("Ingresa el nombre del usuario: ")
			userName, _ := reader.ReadString('\n')
			fmt.Println("Clave Privada:")
			fmt.Println(encryptor.ExportRsaPrivateKeyAsPemStr(searchUserByName(userName, listUsers).PrivateKey))
		case "3":
			fmt.Println("Ingresa el nombre del usuario: ")
			userName, _ := reader.ReadString('\n')
			encrypted, _ := encryptor.ExportRsaPublicKeyAsPemStr(searchUserByName(userName, listUsers).PublicKey)
			//encryptedFormatted := strings.Replace(encrypted, "\n", "\012", -1)
			fmt.Println("Clave Publica:")
			fmt.Println(encrypted)
		case "4":
			// fmt.Println("Ingresa su contraseña: ")
			// plainPassword, _ := reader.ReadString('\n')

			fmt.Println("Ingresa su contraseña: ")
			plainPassword, _ := reader.ReadString('\n')
			plainPassword = strings.Replace(plainPassword, "\n", "", -1)

			fmt.Println("Ingresa su clave publica: ")
			// publicKey, _ := reader.ReadString('\n')
			// publicKey = strings.Replace(publicKey, "\n", "", -1)
			// publicKey = strings.Replace(publicKey, "!", "\n", -1)

			err := exec.Command("rm", "-rf", "/tmp/readline-multiline-public-key").Run()
			if err != nil {
				log.Fatal(err)
			}

			rl, err := readline.NewEx(&readline.Config{
				Prompt:                 "> ",
				HistoryFile:            "/tmp/readline-multiline-public-key",
				DisableAutoSaveHistory: true,
			})
			if err != nil {
				panic(err)
			}
			defer rl.Close()

			for {
				cmd, err := rl.Readline()
				if err != nil {
					break
				}
				rl.SaveHistory(cmd)
			}

			lines, err := readLines(rl.Config.HistoryFile)

			publicKey := ""

			if err != nil {
				log.Fatalf("readLines: %s", err)
			}
			for _, line := range lines {
				publicKey += line
				publicKey += "\n"
			}

			fmt.Print(publicKey)

			pub_parsed, _ := encryptor.ParseRsaPublicKeyFromPemStr(publicKey)

			fmt.Println("\n\nContraseña encriptada: ", encryptor.Encrypt(pub_parsed, plainPassword))
		case "5":
			// fmt.Println("Ingresa su contraseña: ")
			// plainPassword, _ := reader.ReadString('\n')

			fmt.Println("Ingresa su contraseña cifrada: ")
			encryptedPassword, _ := reader.ReadString('\n')
			encryptedPassword = strings.Replace(encryptedPassword, "\n", "", -1)

			err := exec.Command("rm", "-rf", "/tmp/readline-multiline-private-key").Run()
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("Ingresa su clave privada: ")
			rl, err := readline.NewEx(&readline.Config{
				Prompt:                 "> ",
				HistoryFile:            "/tmp/readline-multiline-private-key",
				DisableAutoSaveHistory: true,
			})
			if err != nil {
				panic(err)
			}
			defer rl.Close()

			for {
				cmd, err := rl.Readline()
				if err != nil {
					break
				}
				rl.SaveHistory(cmd)
			}

			lines, err := readLines(rl.Config.HistoryFile)

			privateKey := ""

			if err != nil {
				log.Fatalf("readLines: %s", err)
			}
			for _, line := range lines {
				privateKey += line
				privateKey += "\n"
			}

			fmt.Print(privateKey)

			priv_parsed, _ := encryptor.ParseRsaPrivateKeyFromPemStr(privateKey)

			//encryptor.Decrypt(priv_parsed, encryptedPassword)

			fmt.Println("\n\nContraseña desencriptada: ", encryptor.Decrypt(priv_parsed, encryptedPassword))

		}
	}

}

func menu() string {

	fmt.Print("\n\n\n\n\n\n")

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Ingresa la opción a elegir: ")
	fmt.Println("---------------------")
	fmt.Println("1. Crear nuevo usuario")
	fmt.Println("2. Obtener llave privada de un usuario")
	fmt.Println("3. Obtener llave publica de un usuario")
	fmt.Println("4. Encriptar contraseña")
	fmt.Println("5. Desencriptar contraseña")

	fmt.Print("-> ")
	text, _ := reader.ReadString('\n')
	// convert CRLF to LF
	text = strings.Replace(text, "\n", "", -1)

	return text
}

func pressKeyToContinue() {
	fmt.Println()
	fmt.Print("Presiona cualquier tecla para continuar...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func searchUserByName(name string, users []user.User) *user.User {
	for _, user := range users {
		if name == user.Name {
			return &user
		}
	}
	return nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
