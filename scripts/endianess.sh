
#!/bin/bash

while IFS='' read -r line || [[ -n "$line" ]]; do
        v=` echo "$line"`
        echo $v | tac -rs .. |echo "$(tr -d '\n')"
done < "$1"
