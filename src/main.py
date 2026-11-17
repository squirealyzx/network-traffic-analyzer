import csv
with open("data/network_traffic.csv","r") as file:
    reader = csv.reader(file)
    for row in reader:
        print(row)