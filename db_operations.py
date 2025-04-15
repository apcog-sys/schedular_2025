import mysql.connector
from mysql.connector import Error
import json

def create_connection(db):
    """Create and return a database connection."""
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='event_scheduler2025',
            user='root',
            password='root'
        )
        return connection
    except Error as e:
        print(f"Error while connecting to database: {e}")
        return None
    
def insert_ignore1(db, table_name, insert_data):
    connection = None
    cursor = None
    try:
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor()
            insert_columns = ', '.join(insert_data.keys())
            insert_placeholders = ', '.join(['%s'] * len(insert_data))
            insert_values = list(insert_data.values())
            query = f"""
            INSERT IGNORE INTO {table_name} ({insert_columns})
            VALUES ({insert_placeholders});
            """
            print(query)
            cursor.execute(query, insert_values)
            connection.commit()
            if cursor.rowcount > 0:
                print(f"Row inserted into {table_name} successfully.")
                return True, "Row inserted into entity successfully."
            else:
                print(f"Insert ignored due to duplicate entry in {table_name}.")
                return False
    except Error as e:
        print(f"Error: {e}")
        return False, str(e) 
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def update_entry_old(db,table_name, update_data, where_data):
    print("test - 3" )
    connection = None
    cursor = None
    print("==>>",update_data)
    try:
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor()
            set_clause = ', '.join([f"{key} = %s" for key in update_data.keys()])
            where_clause = ' AND '.join([f"{key} = %s" for key in where_data.keys()])
            update_values = list(update_data.values()) + list(where_data.values())
            query = f"""
            UPDATE {table_name}
            SET {set_clause}
            WHERE {where_clause};
            """
            print("==>>",query)
            print("==>>",update_values)
            cursor.execute(query, update_values)
            connection.commit()
            return cursor.rowcount 
    except Error as e:
        print(f"Error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def update_entry(db, table_name, update_data, where_data):
    """
    Update a record in the database table.

    :param db: Database name
    :param table_name: Table name
    :param update_data: Dictionary of columns to update
    :param where_data: Dictionary of conditions for WHERE clause
    :return: Number of rows updated or False on failure
    """
    print("Starting update_entry function...")

    # Ensure JSON fields are properly serialized
    if "schedule" in update_data and isinstance(update_data["schedule"], dict):
        update_data["schedule"] = json.dumps(update_data["schedule"])  # Convert dict to JSON string

    print("Processed update_data:", update_data)
    
    try:
        
        connection = create_connection(db)
        with connection.cursor() as cursor:
            
            # Construct SQL query dynamically
            set_clause = ', '.join([f"{key} = %s" for key in update_data.keys()])
            where_clause = ' AND '.join([f"{key} = %s" for key in where_data.keys()])
            update_values = list(update_data.values()) + list(where_data.values())

            query = f"""
            UPDATE {table_name}
            SET {set_clause}
            WHERE {where_clause};
            """

            print("Executing Query:", query)
            print("Values:", update_values)

            cursor.execute(query, update_values)
            connection.commit()
            
            print(f"Rows affected: {cursor.rowcount}")
            return cursor.rowcount  # Return number of rows updated

    except Error as e:
        print(f"Database Error: {e}")
        return False

    finally:
        if connection.is_connected():
            connection.close()
            print("Database connection closed.")

def delete_entry(db, table_name, where_data):
    connection = None
    cursor = None
    try:
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor()
            print(where_data)
            for key in where_data.keys():
                print("key: ",key)
            where_clause = ' AND '.join([f"{key} = %s" for key in where_data.keys()])
            where_values = list(where_data.values())
            query = f"DELETE FROM {table_name} WHERE {where_clause};"
            print(query, where_values)
            cursor.execute(query, where_values)
            connection.commit()
            return cursor.rowcount > 0
    except Error as e:
        print(f"Error: {e}")
        return False
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def get_data1(db, table_name, select_fields, where_data=None):
    connection = None
    cursor = None
    print(1)
    try:
        connection = create_connection(db)
        print(2)
        if connection and connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            select_clause = ', '.join(select_fields)
            query = f"SELECT {select_clause} FROM {table_name}"

            if where_data:
                where_clauses = []
                values = []

            
                for key, value in where_data.items():
                    if isinstance(value, str):  # If value is a string, use LIKE for partial match
                        where_clauses.append(f"{key} LIKE %s")
                        values.append(f"%{value}%")  # Adding wildcards for partial matching
                    else:  # For non-string values (e.g., numbers), use exact match
                        where_clauses.append(f"{key} = %s")
                        values.append(value)

                query += f" WHERE {' AND '.join(where_clauses)}"
                cursor.execute(query, values)
            else:
                cursor.execute(query)

            result = cursor.fetchall()
            return result
    except Error as e:
        print(f"Error: {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def get_json_column(db, table_name):
    """Fetch JSON column names dynamically for a given table"""
    try:
        connection = create_connection(db)
        cursor = connection.cursor()
        
        query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = %s AND DATA_TYPE = 'json'"
        cursor.execute(query, (table_name,))
        json_columns = {col[0]: col[0] for col in cursor.fetchall()}  # Auto-map JSON columns

        print(f"[INFO] JSON Columns for table '{table_name}': {json_columns}")  # Debugging log
        return json_columns
    except Error as e:
        print(f"[ERROR] Error fetching JSON columns: {e}")
        return {}
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def get_data3(db, table_name, select_fields, where_data=None):
    connection = None
    cursor = None
    try:
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            select_clause = ', '.join(select_fields)
            query = f"SELECT {select_clause} FROM {table_name}"
            where_clauses = []
            values = []

            # Get JSON columns dynamically
            json_columns = get_json_columns(db, table_name)

            print(f"[INFO] Received filters: {where_data}")  # Debugging log

            if where_data:
                for key, value in where_data.items():
                    column_name = key.split('.')[0]  # Extract the main column (before dot)
                    
                    if column_name in json_columns:
                        # Handle nested JSON fields
                        json_path = key  # Convert dot notation to JSON path
                        json_query = f"JSON_UNQUOTE(JSON_EXTRACT({column_name}, '$.{json_path}'))"
                        where_clauses.append(f"{json_query} LIKE %s")
                        values.append(f"%{value}%")
                        print(f"[INFO] JSON filter added: {json_query} LIKE %s")  # Debugging log
                    else:
                        # Normal LIKE filter for non-JSON text fields
                        where_clauses.append(f"{key} LIKE %s")
                        values.append(f"%{value}%")
                        print(f"[INFO] Normal filter added: {key} LIKE %s")  # Debugging log

                query += f" WHERE {' AND '.join(where_clauses)}"

            print(f"[INFO] Final Query: {query}")  # Debugging log
            print(f"[INFO] Query Values: {values}")  # Debugging log

            cursor.execute(query, values)
            result = cursor.fetchall()

            print(f"[INFO] Query Result: {result}")  # Debugging log
            return result
    except Error as e:
        print(f"[ERROR] {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def get_data4(db, table_name, select_fields, where_data=None):
    """
    Dynamically retrieves data from MySQL, handling both normal and deeply nested JSON filters.
    
    Args:
    - db (str): Database name.
    - table_name (str): Table from which data is fetched.
    - select_fields (list): List of fields to retrieve.
    - where_data (dict, optional): Filtering conditions, including JSON fields.

    Returns:
    - list: Retrieved rows from the database.
    """
    connection = None
    cursor = None
    try:
        # Connect to the database
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor(dictionary=True)

            # Prepare SELECT clause
            select_clause = ', '.join(select_fields)
            query = f"SELECT {select_clause} FROM {table_name}"

            # Prepare WHERE conditions
            where_clauses = []
            values = []

            print(f"[INFO] Received filters: {where_data}")  # Debugging logs

            if where_data:
                for key, value in where_data.items():
                    # Identify the JSON column and its nested path
                    column_name, *json_path_parts = key.split(".")  # Extract base column and JSON path
                    json_path = ".".join(json_path_parts)  # Convert to valid JSON path

                    if json_path:  # If JSON path exists, use JSON_EXTRACT
                        json_query = f"JSON_UNQUOTE(JSON_EXTRACT({column_name}, '$.{json_path}')) LIKE %s"
                        where_clauses.append(json_query)
                        values.append(f"%{value}%")
                        print(f"[INFO] JSON filter added: {json_query} LIKE %s")  # Debug log
                    else:  # Normal SQL column
                        where_clauses.append(f"{key} LIKE %s")
                        values.append(f"%{value}%")
                        print(f"[INFO] Normal filter added: {key} LIKE %s")  # Debug log

                query += f" WHERE {' AND '.join(where_clauses)}"

            print(f"[INFO] Final Query: {query}")  # Debug log
            print(f"[INFO] Query Values: {values}")  # Debug log

            # Execute the query
            cursor.execute(query, values)
            result = cursor.fetchall()

            print(f"[INFO] Query Result: {result}")  # Debug log
            return result
    except Error as e:
        print(f"[ERROR] {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

import mysql.connector
from mysql.connector import Error

def get_data(db, table_name, select_fields, where_data=None):
    """
    Dynamically retrieves data from MySQL, handling both normal and deeply nested JSON fields 
    in SELECT and WHERE clauses.

    Args:
    - db (str): Database name.
    - table_name (str): Table name.
    - select_fields (list): List of fields to retrieve (supports JSON fields).
    - where_data (dict, optional): Filtering conditions (supports JSON fields).

    Returns:
    - list: Retrieved rows from the database.
    """
    connection = None
    cursor = None
    try:
        # Connect to the database
        connection = create_connection(db)
        if connection and connection.is_connected():
            cursor = connection.cursor(dictionary=True)

            # Prepare SELECT clause (handling JSON columns)
            formatted_select_fields = []
            for field in select_fields:
                if "." in field:  # If it's a nested JSON field
                    column_name, *json_path_parts = field.split(".")
                    json_path = ".".join(json_path_parts)
                    formatted_field = f"JSON_UNQUOTE(JSON_EXTRACT({column_name}, '$.{json_path}')) AS `{field}`"
                else:
                    formatted_field = field  # Normal column

                formatted_select_fields.append(formatted_field)

            select_clause = ', '.join(formatted_select_fields)
            query = f"SELECT {select_clause} FROM {table_name}"

            # Prepare WHERE conditions
            where_clauses = []
            values = []

            if where_data:
                for key, value in where_data.items():
                    column_name, *json_path_parts = key.split(".")
                    json_path = ".".join(json_path_parts)

                    if json_path:  # JSON filter
                        json_query = f"JSON_UNQUOTE(JSON_EXTRACT({column_name}, '$.{json_path}')) LIKE %s"
                        where_clauses.append(json_query)
                    else:  # Normal filter
                        where_clauses.append(f"{column_name} LIKE %s")

                    values.append(f"%{value}%")

            if where_clauses:
                query += f" WHERE {' AND '.join(where_clauses)}"

            print(f"[INFO] Final Query: {query}")
            print(f"[INFO] Query Values: {values}")

            # Execute the query
            cursor.execute(query, values)
            result = cursor.fetchall()

            print(f"[INFO] Query Result: {result}")
            return result
    except Error as e:
        print(f"[ERROR] {e}")
        return None
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def get_token_details(token,db):
    """Retrieve data from token_details table for a given token."""
    query = """
    SELECT membership_id, program, entity, role, token
    FROM token_details
    WHERE token = %s
    """

    connection = create_connection(db)
    if connection is None:
        return None
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (token,))
        result = cursor.fetchone()
        return result
    except Error as e:
        print(f"Error while fetching data: {e}")
        return None
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def check_duplicate_entry(connection, table_name, insert_data):
    """ Check which columns caused the duplicate entry. """
    cursor = connection.cursor(dictionary=True)
    conditions = ' AND '.join([f"{col} = %s" for col in insert_data.keys()])
    check_query = f"SELECT * FROM {table_name} WHERE {conditions} LIMIT 1;"
    
    try:
        cursor.execute(check_query, list(insert_data.values()))
        result = cursor.fetchone()
        if result:
            duplicate_columns = [col for col in insert_data if result[col] == insert_data[col]]
            return True, duplicate_columns
        return False, []
    except Error as e:
        print(f"Error checking duplicate entry: {e}")
        return False, []
    finally:
        cursor.close()

def insert_ignore(db, table_name, insert_data):
    connection = create_connection(db)
    cursor = None
    try:
        if connection and connection.is_connected():
            cursor = connection.cursor()
            insert_columns = ', '.join(insert_data.keys())
            insert_placeholders = ', '.join(['%s'] * len(insert_data))
            insert_values = list(insert_data.values())
            query = f"""
            INSERT IGNORE INTO {table_name} ({insert_columns})
            VALUES ({insert_placeholders});
            """
            print(f"Executing Query: {query}")
            cursor.execute(query, insert_values)
            connection.commit()

            if cursor.rowcount > 0:
                print(f"Row inserted into {table_name} successfully.")
                return True, "Row inserted into entity successfully."
            else:
                # Identify which columns caused the duplicate entry
                is_duplicate, duplicate_columns = check_duplicate_entry(connection, table_name, insert_data)
                if is_duplicate:
                    print(f"Insert ignored due to duplicate entry in {table_name}. Conflicting columns: {duplicate_columns}")
                    return False, f"Insert ignored due to duplicate entry. Conflicting columns: {duplicate_columns}"
                else:
                    return False, "Insert ignored, but no exact duplicate found."
    except Error as e:
        print(f"Error: {e}")
        return False, str(e)
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#data = get_data("event_scheduler2025","entity", ['*'],{'entity_id': 1})
#print(data)

#data = update_entry("event_scheduler2025", "entity",{"entity_name": "Updated Entity Name"},{"entity_id": "1"})

#is_deleted = delete_entry("event_scheduler2025","entity", {"entity_id": "1"})