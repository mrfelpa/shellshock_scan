# Installation

- Make sure you have Python 3 installed. 
- Install dependencies using:

          pip install requests rich argparse command.

# Running the Tool

- Run the script with the command:

          python shellshock_tester.py
  
- You will be prompted for URLs for testing or the path to a file containing URLs (separated by line).
- You can define the number of threads for parallelism and the name of a file to save the results in JSON format.
- Example:

          python shellshock_tester.py -u www.example1.com www.example2.com -t 10 -o results.json
  

![Image_test](https://github.com/user-attachments/assets/588b4e63-fca8-40dd-a420-c9352c2228da)


# Disclaimer

  - Running this script against systems that you do not have explicit permission to may be considered malicious activity. Use the tool only in authorized environments for testing and auditing purposes.
  - Shellshock is a critical vulnerability. If you find a vulnerability, we strongly recommend applying security patches to affected servers as soon as possible.

# Contributing to the Project

We value contributions. Feel free to submit pull requests with improvements, bug fixes, or new features.
