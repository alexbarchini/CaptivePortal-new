const { z } = require('zod');

const cleanDigits = (value = '') => String(value).replace(/\D/g, '');

function formatCPF(cpfInput) {
  const cpf = cleanDigits(cpfInput).slice(0, 11);
  if (cpf.length !== 11) return cpf;
  return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
}

function isValidCPF(cpfInput) {
  const cpf = cleanDigits(cpfInput);
  if (!cpf || cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) return false;

  const calcDigit = (base, factor) => {
    let total = 0;
    for (const digit of base) {
      total += Number(digit) * factor--;
    }
    const remainder = total % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };

  const d1 = calcDigit(cpf.slice(0, 9), 10);
  const d2 = calcDigit(cpf.slice(0, 10), 11);
  return d1 === Number(cpf[9]) && d2 === Number(cpf[10]);
}

function normalizeBrazilianPhone(phoneInput) {
  const digits = cleanDigits(phoneInput);
  const local = digits.startsWith('55') ? digits.slice(2) : digits;
  if (!/^\d{11}$/.test(local)) {
    return null;
  }

  const ddd = local.slice(0, 2);
  const number = local.slice(2);
  if (number[0] !== '9') {
    return null;
  }

  return `+55${ddd}${number}`;
}

function isValidEmail(emailInput) {
  const email = String(emailInput || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

const registerSchema = z.object({
  fullName: z.string().trim().min(5, 'Informe o nome completo.').max(120, 'Nome muito longo.'),
  cpf: z.string().transform(cleanDigits).refine((v) => isValidCPF(v), 'CPF inválido.'),
  phone: z.string().transform(normalizeBrazilianPhone).refine((v) => Boolean(v), 'Telefone inválido.'),
  email: z.string().trim().toLowerCase().refine((v) => isValidEmail(v), 'E-mail inválido.'),
  password: z.string().min(8, 'A senha deve ter no mínimo 8 caracteres.'),
  confirmPassword: z.string(),
  accepted_terms: z.literal('on', { errorMap: () => ({ message: 'Aceite os Termos de Uso.' }) }),
  accepted_privacy: z.literal('on', { errorMap: () => ({ message: 'Aceite a Política de Privacidade.' }) }),
  accepted_processing: z.literal('on', { errorMap: () => ({ message: 'Autorize o tratamento de dados.' }) })
}).refine((data) => data.password === data.confirmPassword, {
  message: 'As senhas não conferem.',
  path: ['confirmPassword']
});

const loginSchema = z.object({
  cpf: z.string().transform(cleanDigits).refine((v) => isValidCPF(v), 'CPF inválido.'),
  password: z.string().min(1, 'Senha obrigatória.')
});

const verifySmsSchema = z.object({
  lsid: z.string().min(10, 'Sessão inválida.'),
  code: z.string().transform(cleanDigits).refine((v) => /^\d{6}$/.test(v), 'Código inválido.')
});

module.exports = {
  registerSchema,
  loginSchema,
  verifySmsSchema,
  cleanDigits,
  isValidCPF,
  normalizeBrazilianPhone,
  isValidEmail,
  formatCPF
};
