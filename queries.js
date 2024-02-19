const queryByEmail = 'SELECT * FROM users WHERE email = $1';
const queryByPassword = 'SELECT * FROM users WHERE password = $1';
const insertUser = 'INSERT INTO users (email, password) VALUES ($1, $2)';

export default {
    queryByEmail,
    queryByPassword,
    insertUser
}