#!/bin/bash
# small script to create a custom wordfile manually and a mangled file with john

# define wordfile name
echo "wordfile name?"
read WF

# create wordfile with first entry
echo "first entry (q for quit):"
read ZF
echo $ZF > $WF

# additional wordfile entries
while [ $ZF != q ]; do
	echo "additional entry (q for quit):"
	read ZF
	echo $ZF >> $WF
done

# john the ripper word mangling
echo "let john do some magic... creating $WF _mangled?"
john --wordlist=$WF --rules --stdout > $WF"_mangled"
