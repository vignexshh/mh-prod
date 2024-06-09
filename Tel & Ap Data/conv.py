import pandas as pd

# Read the input data from the file
with open("/Users/namanmuktha/Desktop/crewlabs/mh-prod/Tel & Ap Data/temp.txt", "r") as file:
    data_all = file.read()

# Convert the data into lines
lines_all = data_all.split('\n')

# Define the column names
columns = ['COLLEGE', 'RANK', 'LOC', 'CAT', 'SX','MINOR','NRI','ACDS','EWS','PHASE']

# Initialize variables
college = None
parsed_data = []

# Parse the data and extract necessary information
for line in lines_all:
    if line.startswith("COLL ::"):
        # Extract college name from the line
        college = line.split("-")[-1].strip()
    elif line.strip() != '' and not line.startswith(("----", "CRS", "RANK")):
        split_data = line.split()
        rank = split_data[0]
        loc, cat, sx, minor,nri,acds , ews, phase = '', '', '', '', '','','',''
        for item in split_data:
            if item in ['OU', 'AU', 'SVU','NL']:
                loc = item
            elif item in ['OC', 'SC', 'ST', 'BCA', 'BCB', 'BCD', 'BCE','BCC']:
                cat = item
            elif item in ['M', 'F']:
                sx = item
            elif item in ['NRI']:
                nri = item
            elif item in ['MSM']:
                minor = item
            elif item in ['YES']:
                acds= item
            elif item in ['EWS']:
                ews = item
            elif split_data[::-1][0].split('-')[::-1][0] in ['P1','P2','P3','P4','P5','P6','P7']:
                phase = split_data[::-1][0].split('-')[::-1][0]
        parsed_data.append([college, rank, loc, cat, sx,minor ,nri,acds ,ews, phase])

# Create DataFrame
df_all = pd.DataFrame(parsed_data, columns=columns)

# Write the DataFrame to a CSV file
df_all.to_csv("telangana_management5.csv", index=False)

print("CSV file created successfully.")