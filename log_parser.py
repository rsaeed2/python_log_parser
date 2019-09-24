#!/usr/bin/python3
#Name: Rohan Saeed                  Course: SRT311SAA                Assignment 1
import sys
import re

def check_ips(src,dst):
    """This function checks the source and destination IP's if they are entered correctly and returns a code 0, 1 or 2"""
    a = "Not Checked"
    b = "Not Checked"
    if re.match(ip_pattern,sys.argv[2]):            #Check if the source IP matches the IP regex pattern
        a = "Yes"
    else:
        sys.exit("Wrong format for source IP, please try again")
    if dst is not False:
        if re.match(ip_pattern,sys.argv[3]):            #Check if the destination IP matches the IP regex pattern
            b = "Yes"
        else:
            sys.exit("Wrong format for destination IP, please try again")
    if a == "Yes" and b == "Not Checked":                #Based on checking the 3rd and 4th argument, finally check if it is correctly entered
        return "1"
    elif a == "Yes" and b == "Yes":
        return "2"
    else:
        return "0"

def parse_file():
    """This function parses the file to check for IP's and size in the input file and returns a list"""
    output_line_list = []
    try:
        ip_pattern2 = r'^[0-9]{2}\:[0-9]{2}\:[0-9]{2}\.[0-9]{6}\sIP.*length.*$' #Create regex to parse file lines
        ip_pattern3 = r'IP\s.*?\s\>'                                        
        ip_pattern3_1 = r'\>\s.*?\:'
        ip_pattern4 = r'[0-9]{1,4}$'                                        
        input_file = open(sys.argv[1], "r")                       
        input_line_list = input_file.read().splitlines()          #Make a list called lines from the input file and split at each line
        input_file.close()                                        
        for line in input_line_list:
            if re.findall(ip_pattern2,line):                      #If a line has an IP pattern in it add it to list  
                new_source = re.findall(ip_pattern3,line)            
                new_dest = re.findall(ip_pattern3_1,line)
                new_size = re.findall(ip_pattern4,line)
                new_line = new_source + new_dest + new_size
                new_line[0] = new_line[0].strip("IP ")
                new_line[0] = re.sub('[:>\s]','',new_line[0])            #Process the line to remove unwanted bits
                new_line[1] = re.sub('[:>\s]','',new_line[1])            
                output_line_list.append(new_line)                        #Add the processed line to the output list   
        def remove_ports(x):
            """This functions removes ports from each line in the output list"""
            port_regex = r'([0-9]{1,5})$'                                #Regex to find port #'s at end of each IP ($)
            for line in x:
                for sub_line in line:
                   if re.findall(port_regex,sub_line): 
                        line[0] = re.sub(port_regex,'',line[0])     #Remove the port numbers in each entry in the list
                        line[1] = re.sub(port_regex,'',line[1])
                line[0] = line[0][0:len(line[0])-1]                 
                line[1] = line[1][0:len(line[1])-1]     
            return x            
        output_line_list = remove_ports(output_line_list)
        return output_line_list                                     
    except IndexError:                                              
        print("No file name was entered, please enter a file name")   
    except FileNotFoundError:                                       
        print("No such file exists, try again")     

def filter_results(dict1,num,src,dst):
    """This function filters the results of TCPdump based on the user input arguments and returns a dictionary"""
    if num == "0":
        return dict1
    if num == "1":    
        tmpdict = dict1.copy()          #This creates a temporary dictionary called tmpdict
        for x,y in tmpdict.items():
            if src not in x:
                del(dict1[x])           #This checks if the source is in the dictionary, else delete the item from dictionary
        return dict1              
    elif num == "2":
        srcdest = (src+","+dst)
        tmpdict = dict1.copy()
        for x,y in tmpdict.items():     #This checks if the source and destionation is in the dictionary, else delete the item from dictionary
            if srcdest not in x:
                del(dict1[x])
        return dict1                    #Return the newly modified and filtered dictionary
    else:
        return dict1

def sort_list(dict2):
    """This function sorts the list by highest total size in descending order and returns a sorted dictionary"""
    sorted_dict = dict(sorted(dict2.items(), key=lambda x: x[1], reverse=True)) #This sorts the dictionary by value, largest on top
    return sorted_dict

def print_list(dict2):
    """This function prints the final output list and makes it look user friendly"""
    dictList = []                   
    for key, value in sorted_dictionary.items():        #Convert the dictionary back to a list
        dictList.append([key,value])
    for line in dictList:                               
        line[0] = re.sub('[,]','\t Dest: ',line[0])     #Print out the list and make it look good
        line[1] = "Size: " + str(line[1])
        print("Source:", *line,sep='\t')

# ~~~~~~~~~~~~~~~~~~~~~ ACTUAL PROGRAM AT START ~~~~-~~~~~~~~~~~~~~~~~~~~ # 
ip_pattern = r'^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$' #IP regex to match the IP pattern
ip_return = 0      #1 = proper source IP correctly provided, 2 = source and destination ip are correctly provided
if len(sys.argv) <= 2:      
    source_ip = False
    dest_ip = False
elif len(sys.argv) == 3:        #and set variables based on # of input arguments
    source_ip = sys.argv[2]
    dest_ip = False
    ip_return = check_ips(source_ip, False)      #If a source/dest IP is given, check if the IP format is correct
elif len(sys.argv) == 4:
    source_ip = sys.argv[2]
    dest_ip = sys.argv[3]
    ip_return = check_ips(source_ip,dest_ip)     #Set source and destinaion IP's, otherwise set them to False
if ip_return == 1:
    source_ip = sys.argv[2]
elif ip_return == 2:
    source_ip = sys.argv[2]
    dest_ip = sys.argv[3]
parsed_list = parse_file()          #Run the parse_file function to load the file and return a list of each line
parsed_dict = {}                    
for line in parsed_list:
    parsed_dict[line[0]+","+line[1]] = 0    #Convert list to a dictionary to allow adding size of packets
for line in parsed_list:            
    parsed_dict[line[0]+","+line[1]] += int(line[2])    #Add up the values of each size in this dictionary
returned_filtered_results = filter_results(parsed_dict, ip_return, source_ip, dest_ip)  
sorted_dictionary = sort_list(returned_filtered_results)    #Then we sort the filtered results by size using the sort_list function
print_list(sorted_dictionary)       #Finally, we print the sorted dictionary using the print_list function
