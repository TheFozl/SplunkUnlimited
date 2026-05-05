# SplunkUnlimited
Enjoy the full power of Splunk Enterprise at no cost.

## Usage

### 1. (Optional) Download Splunk Enterprise if you don't already have it 
You can download it at: https://www.splunk.com/en_us/download/splunk-enterprise.html\
or can you also choose any version here: https://livehybrid.github.io/downloadSplunk\
Install it and follow the official guide.

### 2. Stop the server
Stop the splunk server:\
On Linux:\
```# /opt/splunk/bin/splunk stop```

### 3. Run the script on the ```splunkd``` file
Make sure you have the necessary permissions to edit the file.\
```# python3 SplunkUnlimited.py /opt/splunk/bin/splunkd```

### 4. Start the server
Start the splunk server:\
On Linux:\
```# /opt/splunk/bin/splunk start```

### 5. Log in to the web UI and upload the license
Once the server has started, go to the license settings.\
You can now add a new license and select the ```Unlimited.license``` file.

### 6. Restart the server
Restart the splunk server:\
On Linux:\
```# /opt/splunk/bin/splunk restart```

### 6. Enjoy
You can now use Splunk Enterprise for free, with no limit!

## Force-mode
If, for any reason, your ```splunkd``` file has a different hash, you can use the force-mode to patch it anyway.\
First, make sure your version is supported:\
```# python3 SplunkUnlimited.py --list```

Then, start the script with the force-mode:\
```# python3 SplunkUnlimited.py /opt/splunk/bin/splunkd --force-mode```

The script will run as usual, except that it will allow you to manually select the patch to apply if it cannot find the hash.

## Troubleshooting

### I'm getting an "Permission Denied" error message
Make sure you have the necessary permissions to modify the file.\
On Linux, the ```splunkd``` file usually belongs to the ```splunk``` user.\
Try running the script using that account or the ```root``` account.

### I'm getting an "Hash not found in the hash database..." error message
Your version is not supported by the script.\
You can open an issue on GitHub to request that it be added.

### I'm getting any other error message
Try downloading the script again.\
If it still doesn't work, run the script with the ```-v``` or ```--verbose``` option and open an issue on GitHub with the output.
