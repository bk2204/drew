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

bool Integer::GetBit(size_t bit) const
{
	Integer mask(*this), res(*this), zero(*this);
	mask.SetValue(1);
	mask = mask.ShiftLeft(bit);
	zero.Zero();
	bn->functbl->bitwiseand(res.bn, bn, mask.bn);
	return bn->functbl->compare(res.bn, zero.bn, 0);
}

size_t Integer::ByteSize() const
{
	return bn->functbl->nbytes(bn);
}


PrimePoint::PrimePoint() : identity(true)
{
}

PrimePoint::PrimePoint(const Integer &x0, const Integer &y0) :
	x(x0), y(y0), identity(false);
{
}

typedef EllipticCurveOverPrimeField::Point PrimePoint

EllipticCurveOverPrimeField::EllipticCurveOverPrimeField(const Integer &p,
		const Integer &aval, const Integer &bval) : prime(p), aval(a), bval(b)
{

}

// This reimplemented from Crypto++.
PrimePoint EllipticCurveOverPrimeField::Identity() const
{
	return Point();
}

PrimePoint EllipticCurveOverPrimeField::Add(const Point &p, const Point &q)
	const
{
	if (p.identity)
		return q;
	if (q.identity)
		return p;
	if (!p.x.Compare(q.x))
		return !p.y.Compare(q.y) ? Double(p) : Identity();
	Integer s = (p.y.Subtract(q.y)).Divide(p.x.Subtract(q.x)).Mod(prime);
	Point pt;
	pt.x = s.Square().Subtract(p.x).Subtract(q.x).Mod(prime);
	pt.y = s.Multiply(p.x.Subtract(pt.x)).Subtract(p.y).Mod(prime);
	return pt;
}

PrimePoint EllipticCurveOverPrimeField::Double(const Point &p) const
{
	Integer zero, three;
	zero.Zero();
	three.SetValue(3);
	if (p.identity || !p.y.Compare(zero))
		return Identity();
	Integer snum = three.Multiply(p.x.Square()).Add(a);
	Integer s = snum.Divide(p.y.ShiftLeft(1)).Mod(prime);
	Point pt;
	pt.x = s.Square().Subtract(p.x.ShiftLeft(1)).Mod(prime);
	pt.y = s.Multiply(p.x.Subtract(pt.x)).Subtract(p.y).Mod(prime);
	return pt;
}

PrimePoint EllipticCurveOverPrimeField::Multiply(const Point &p,
		const Integer &k) const
{
	Integer l(k);
	Point q;

	l.Zero();
	return Multiply(p, k, q, l);
}

PrimePoint EllipticCurveOverPrimeField::Multiply(const Point &p,
		const Integer &k, const Point &q, const Integer &l) const
{
	Integer z = p.Add(q);
	Integer r = Point();
	size_t m = std::max(k.ByteSize(), l.ByteSize()) * 8;

	for (int i = m-1; i >= 0; i--) {
		int bits = (k.GetBit(i) << 1) | l.GetBit(i);
		r = Double(r);

		switch (bits) {
			case 1:
				r = Add(r, q);
				break;
			case 2:
				r = Add(r, p);
				break;
			case 3:
				r = Add(r, z);
				break;
			case 0:
				break;
		}
	}
	return r;
}
