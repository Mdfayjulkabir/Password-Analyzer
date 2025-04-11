# Password Analyzer 🔐

A Python utility for evaluating password strength, detecting weaknesses, and recommending secure password practices.

## Features
✅ Checks password strength based on length, character variety, and entropy  
✅ Detects weaknesses (common passwords, repeated sequences, dictionary words)  
✅ Checks if the password has been exposed in data breaches (HIBP API)  
✅ Suggests a secure random password  

---

## 🛠 Installation (Linux)
### **1️⃣ Install Python** (Skip if already installed)
Most Linux distributions come with Python pre-installed. To check:
```sh
python3 --version
```
If not installed, use:
```sh
sudo apt update && sudo apt install python3 python3-pip -y  # Debian/Ubuntu
sudo dnf install python3 python3-pip -y  # Fedora
sudo pacman -S python python-pip  # Arch
```

### **2️⃣ Clone the Repository**
```sh
git clone https://github.com/Mdfayjulkabir/Password-Analyzer.git
cd Password-Analyzer
```


## 🚀 Usage
Run the script:
```sh
python3 password_analyzer.py
```

Enter a password when prompted, and the tool will analyze it.

---

## 📝 Example Output
```
🔍 Password Analysis:
🔹 Strength: Strong (Entropy: 74.85 bits)

✅ No weaknesses detected. Great password!

🔑 Suggested Secure Password: z#7XGp@Y91Qw!R&f
```

---

## 🔧 Troubleshooting
- If `pip3` is not found, install it:  
  ```sh
  sudo apt install python3-pip -y
  ```
- If you get **Permission Denied**, try running with `sudo` or setting execution permissions:  
  ```sh
  chmod +x password_analyzer.py
  ```

---

## 📜 License
This project is open-source under the **MIT License**.
