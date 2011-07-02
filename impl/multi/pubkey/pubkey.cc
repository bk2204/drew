#include "pubkey.hh"

Integer::Integer(drew_bignum_t *bignum)
{
	bn = bignum;
}

Integer::Integer(const Integer &i)
{
	i.bn->functbl->clone(this->bn, i.bn);
}

void Integer::Zero()
{
	bn->functbl->setzero(bn);
}

int Integer::GetValue(uint8_t *p, size_t len)
{
	return bn->functbl->bytes(bn, p, len);
}

void Integer::SetValue(const uint8_t *p, size_t len)
{
	bn->functbl->setbytes(bn, p, len);
}

void Integer::SetValue(long l)
{
	bn->functbl->setsmall(bn, l);
}

Integer Integer::Negate()
{
	Integer res(*this);
	bn->functbl->negate(res.bn, bn);
	return res;
}

Integer Integer::GetAbsoluteValue() const
{
	Integer res(*this);
	bn->functbl->abs(res.bn, bn);
	return res;
}

int Integer::Compare(Integer &b) const
{
	return bn->functbl->compare(bn, b.bn, 0);
}

int Integer::CompareMagnitudes(Integer &b) const
{
	return bn->functbl->compare(bn, b.bn, DREW_BIGNUM_ABS);
}

Integer Integer::Add(const Integer &a) const
{
	Integer res(*this);
	bn->functbl->add(res.bn, bn, a.bn);
	return res;
}

Integer Integer::Subtract(const Integer &a) const
{
	Integer res(*this);
	bn->functbl->sub(res.bn, bn, a.bn);
	return res;
}

Integer Integer::ShiftLeft(size_t cnt) const
{
	Integer res(*this);
	bn->functbl->shiftleft(res.bn, bn, cnt);
	return res;
}

Integer Integer::ShiftRight(size_t cnt) const;
{
	Integer res(*this);
	bn->functbl->shiftright(res.bn, bn, cnt);
	return res;
}

Integer Integer::Multiply(const Integer &a) const;
{
	Integer res(*this);
	bn->functbl->mul(res.bn, bn, a.bn);
	return res;
}

Integer Integer::Divide(const Integer &a) const;
{
	Integer res(*this);
	bn->functbl->div(res.bn, NULL, bn, a.bn);
	return res;
}

Integer Integer::Divide(Integer &rem, const Integer &a) const;
{
	Integer res(*this);
	bn->functbl->div(res.bn, rem.bn, bn, a.bn);
	return res;
}

Integer Integer::Mod(const Integer &m) const;
{
	Integer res(*this);
	bn->functbl->mod(res.bn, bn, m.bn);
	return res;
}

Integer Integer::ExponentialMod(const Integer &exp, const Integer &m) const;
{
	Integer res(*this);
	bn->functbl->expmod(res.bn, bn, exp.bn, a.bn);
	return res;
}

Integer Integer::InverseMod(const Integer &m) const;
{
	Integer res(*this);
	bn->functbl->invmod(res.bn, bn, m.bn);
	return res;
}

Integer Integer::MultiplyMod(const Integer &mul, const Integer &m) const;
{
	Integer res(*this);
	bn->functbl->mul(res.bn, bn, mul.bn);
	bn->functbl->mod(res.bn, res.bn, m.bn);
	return res;
}

Integer Integer::Square() const;
{
	Integer res(*this);
	bn->functbl->square(res.bn, bn);
	return res;
}

