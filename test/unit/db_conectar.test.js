// Mock automático de la base de datos
jest.mock('../../models/db_conectar');

describe('Database Mock Tests', () => {
  test('should mock connection successfully', () => {
    // La conexión ya está mockeada, no se ejecuta la real
    const connection = require('../../models/db_conectar');
    
    expect(connection.connect).toHaveBeenCalled;
    expect(typeof connection.query).toBe('function');
  });
});