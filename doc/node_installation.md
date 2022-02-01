NODE INSTALLATION INSTRUCTION 
====================
This installation instruction is for a Linux based system on x64 architecture - version 16.04 and 18.04



Install the dependencies
---------------------
Use the following script to auto install the required dependencies. It will also create a swap file if required

On 16.04 x64
------
	curl https://bitcoinafrica.org/1604/depends | bash


On 18.04 x64
------
	curl https://bitcoinafrica.org/1804/depends | bash


Prepare the daemon
---------------------
Download the followings files 

	sudo wget https://bitcoinafrica.org/node/bitcoinafrica.zip
  
Extract it

	sudo unzip bitcoinafrica.zip

Copy the ".bitcoinafrica" folder at your desired location.

At the ".bitcoinafrica/bitcoinafrica.conf" file, replace RPCUSER and RPCPASSWORD by your desired rpcuser and rpcpassword. Then save the file

Start the daemon
---------------------
	bitcoinafricad -rpcuser=RPCUSER -rpcpassword=RPCPASSWORD -datadir=/LOCATION/.bitcoinafrica -conf=bitcoinafrica.conf -daemon -txindex

Replace "LOCATION" by your desired location of the ".bitcoinafrica" folder

And

Replace RPCUSER and RPCPASSWORD by your desired rpcuser and rpcpassword.

---------------------

Your node is now started and connected to the Bitcoin-Africa Coin network


