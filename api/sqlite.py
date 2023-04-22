import sqlite3 as sq


def db_start():
    """
    создаем таблицу с компаниями
    """
    global db, cur

    db = sq.connect('emotions.db')
    cur = db.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS companies(id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "company_name TEXT, login TEXT, password TEXT, email TEXT, info TEXT)")
    db.commit()


def db_create_company(company_name):
    """
    создаем таблицу для конкретной компании
    """
    cur.execute("INSERT INTO companies (company_name) VALUES (?)", (company_name, ))

    cur.execute("CREATE TABLE IF NOT EXISTS '{company_name}'(id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "photo_date DATE,"
                "photo_time TIME,"
                "photo_emotion TEXT,"
                "sex INT,"
                "age INT)".format(company_name=company_name))

    db.commit()


def db_get_all_data(company_name):
    db_start()
    """
    возвращает данные
    """
    notes = cur.execute("SELECT * FROM '{company_name}'".format(company_name=company_name)).fetchall()
    return notes


def db_get_all_locations(company_name):
    db_start()
    """
    возвращает данные
    """
    notes = cur.execute("SELECT * FROM locations WHERE company_name = '{company_name}'".format(company_name=company_name)).fetchall()
    return notes


def db_get_all_companies():
    db_start()
    """
    возвращает данные
    """
    notes = cur.execute("SELECT * FROM companies".format()).fetchall()
    return notes


def db_add_notification_in_table(company_name):
    db_start()
    """
    добавляем запись в таблицу (надо больше параметров в функцию передавать. Но это потом)
    """
    cur.execute("INSERT INTO '{company_name}' (photo_date, photo_time, photo_emotion, sex, age) "
                "VALUES(?, ?, ?, ?, ?)".format(company_name=company_name),
                ('21/03/2023', '17:00', "{'angry': 0.0, 'disgust': 0.0, 'fear': 0.0, 'happy': 0.99, 'sad': 0.0, 'surprise': 0.0, 'neutral': 0.01}", 0, 74))
    cur.execute("INSERT INTO '{company_name}' (photo_date, photo_time, photo_emotion, sex, age) "
                "VALUES(?, ?, ?, ?, ?)".format(company_name=company_name),
                ('24/03/2023', '17:00',
                 "{'angry': 0.0, 'disgust': 0.0, 'fear': 0.0, 'happy': 0.5, 'sad': 0.49, 'surprise': 0.0, 'neutral': 0.01}",
                 0, 74))


    for i in range(10):
        cur.execute("INSERT INTO '{company_name}' (photo_date, photo_time, photo_emotion, sex, age) "
                    "VALUES(?, ?, ?, ?, ?)".format(company_name=company_name),
                    ('24/03/2023', '17:00',
                     "{'angry': 0.0, 'disgust': 0.0, 'fear': 0.5, 'happy': 0, 'sad': 0.49, 'surprise': 0.0, 'neutral': 0.01}",
                     0, 74))
    for i in range(10):
        cur.execute("INSERT INTO '{company_name}' (photo_date, photo_time, photo_emotion, sex, age) "
                    "VALUES(?, ?, ?, ?, ?)".format(company_name=company_name),
                    ('29/03/2023', '17:00',
                     "{'angry': 0.5, 'disgust': 0.0, 'fear': 0, 'happy': 0, 'sad': 0.49, 'surprise': 0.0, 'neutral': 0.01}",
                     0, 74))

    db.commit()

