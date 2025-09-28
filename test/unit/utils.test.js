const bcrypt = require('bcrypt');

// Pruebas para funciones puras (sin dependencias externas)
describe('Password Hashing', () => {
  test('should hash password correctly', async () => {
    const password = 'myPassword123';
    const hashedPassword = await bcrypt.hash(password, 10);
    
    expect(hashedPassword).not.toBe(password);
    expect(hashedPassword.length).toBeGreaterThan(10);
  });

  test('should compare password correctly', async () => {
    const password = 'testPassword';
    const hashed = await bcrypt.hash(password, 10);
    
    const match = await bcrypt.compare(password, hashed);
    expect(match).toBe(true);
    
    const noMatch = await bcrypt.compare('wrongPassword', hashed);
    expect(noMatch).toBe(false);
  });
});