#ifndef PUBKEY_HH
#define PUBKEY_HH

class Integer
{
	public:
		Integer(drew_bignum_t *bignum);
		Integer(const Integer &i);
		void Zero();
		int GetValue(uint8_t *, size_t);
		void SetValue(const uint8_t *, size_t);
		void SetValue(long);
		Integer Negate();
		Integer GetAbsoluteValue() const;
		int Compare(Integer &);
		int CompareMagnitudes(Integer &);
		Integer Add(const Integer &a) const;
		Integer Subtract(const Integer &a) const;
		Integer Multiply(const Integer &a) const;
		Integer ShiftLeft(size_t cnt) const;
		Integer ShiftRight(size_t cnt) const;
		Integer Divide(const Integer &a) const;
		Integer Divide(Integer &rem, const Integer &a) const;
		Integer Mod(const Integer &m) const;
		Integer ExponentialMod(const Integer &exp, const Integer &m) const;
		Integer InverseMod(const Integer &m) const;
		Integer MultiplyMod(const Integer &mul, const Integer &m) const;
		Integer Square() const;
	protected:
	private:
		drew_bignum_t *bn;
};

#endif
