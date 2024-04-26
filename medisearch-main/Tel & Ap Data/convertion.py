import csv
from docx import Document

def convert_word_table_to_csv(word_file_path, csv_file_path):
    # Load the Word document
    doc = Document(word_file_path)

    # Open a CSV file for writing
    with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)

        # Iterate through tables in the Word document
        for table in doc.tables:
            # Iterate through rows in the table
            for row in table.rows:
                # Extract data from each cell in the row
                row_data = [cell.text.strip() for cell in row.cells]

                # Write the row data to the CSV file
                csv_writer.writerow(row_data)

if __name__ == "__main__":
    # Provide the path to the Word document and the desired CSV file
    word_file_path = "C:/Users/elige\Downloads/1.Telangana_NEET_2023_Data_compressed.docx"
    csv_file_path = 'output.csv'

    # Call the function to convert Word table data to CSV
    convert_word_table_to_csv(word_file_path, csv_file_path)

    print(f"Conversion complete. CSV file saved at: {csv_file_path}")
