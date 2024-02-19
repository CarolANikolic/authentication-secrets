import pg from "pg";

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "secrets",
    password: "Bazingadatabase$",
    port: 5432
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to PostgreSQL database:', err);
    } else {
        console.log('Connected to PostgreSQL database successfully!');
        db.query('SELECT NOW()', (err, result) => {
            if (err) {
                console.error('Error executing query:', err);
            } else {
                console.log('Query time stamp:', result.rows[0]);
            }
        });
    }
});

export default db