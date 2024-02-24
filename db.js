import pg from "pg";
import env from "dotenv";

env.config();

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DB,
    password: process.env.PG_PASS,
    port: process.env.PG_PORT
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