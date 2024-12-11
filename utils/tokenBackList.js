
let tokenBlacklist = [];

const checkBlacklist = (token) => {
    return tokenBlacklist.includes(token);
};

module.exports = {
    tokenBlacklist, checkBlacklist
}