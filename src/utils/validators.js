const { z } = require('zod');

const cleanDigits = (value = '') => String(value).replace(/\D/g, '');

function isValidCPF(cpfInput) {
  const cpf = cleanDigits(cpfInput);
  if (!cpf || cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;

  const calcDigit = (base, factor) => {
    let total = 0;
    for (const digit of base) {
      total += Number(digit) * factor--;
    }
    const result = (total * 10) % 11;
    return result === 10 ? 0 : result;
  };

  const d1 = calcDigit(cpf.slice(0, 9), 10);
  const d2 = calcDigit(cpf.slice(0, 10), 11);
  return d1 === Number(cpf[9]) && d2 === Number(cpf[10]);
}

const registerSchema = z.object({
  cpf: z.string().transform(cleanDigits).refine((v) => isValidCPF(v), 'CPF inválido.'),
  phone: z.string().transform(cleanDigits).refine((v) => v.length >= 10 && v.length <= 13, 'Telefone inválido.'),
  password: z
    .string()
    .min(10, 'A senha deve ter no mínimo 10 caracteres.')
    .regex(/[A-Z]/, 'A senha deve conter letra maiúscula.')
    .regex(/[a-z]/, 'A senha deve conter letra minúscula.')
    .regex(/[0-9]/, 'A senha deve conter número.')
    .regex(/[^A-Za-z0-9]/, 'A senha deve conter caractere especial.'),
  confirmPassword: z.string(),
  accepted_terms: z.literal('on', { errorMap: () => ({ message: 'Aceite os Termos de Uso.' }) }),
  accepted_privacy: z.literal('on', { errorMap: () => ({ message: 'Aceite a Política de Privacidade.' }) }),
  accepted_processing: z.literal('on', { errorMap: () => ({ message: 'Autorize o tratamento de dados.' }) })
}).refine((data) => data.password === data.confirmPassword, {
  message: 'As senhas não conferem.',
  path: ['confirmPassword']
});

const loginSchema = z.object({
  cpf: z.string().transform(cleanDigits).refine((v) => v.length === 11, 'CPF inválido.'),
  password: z.string().min(1, 'Senha obrigatória.')
});

module.exports = { registerSchema, loginSchema, cleanDigits };
