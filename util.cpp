#include "util.h"

/** Find out how many cores the CPU has. **/
int GetTotalCores()
{
	int nProcessors = boost::thread::hardware_concurrency();
	if (nProcessors < 1)
		nProcessors = 1;
			
	return nProcessors;
}


uint64 mpz2uint64(mpz_t n)
{
    unsigned int lo, hi;
    mpz_t tmp;

    mpz_init( tmp );
    mpz_mod_2exp( tmp, n, 64 );

    lo = mpz_get_ui( tmp );
    mpz_div_2exp( tmp, tmp, 32 );
    hi = mpz_get_ui( tmp );

    mpz_clear( tmp );

    return (((uint64)hi) << 32) + lo;
}

int bignum2mpz(const BIGNUM *bn, mpz_t g)
{
	bn_check_top(bn);
	if(((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) && (BN_BITS2 == GMP_NUMB_BITS)) 
	{
		/* The common case */
		if(!_mpz_realloc (g, bn->top))
			return 0;
		memcpy(&g->_mp_d[0], &bn->d[0], bn->top * sizeof(bn->d[0]));
		g->_mp_size = bn->top;
		if(bn->neg)
			g->_mp_size = -g->_mp_size;
			
		return 1;
	}
	else
	{
		char *tmpchar = BN_bn2hex(bn);
		
		if(!tmpchar)
			return 0;
		
		OPENSSL_free(tmpchar);
		
		return 0;
	}
}
 
static int mpz2bignum(mpz_t g, BIGNUM *bn)
{
	if(((sizeof(bn->d[0]) * 8) == GMP_NUMB_BITS) && (BN_BITS2 == GMP_NUMB_BITS))
	{
		/* The common case */
		int s = (g->_mp_size >= 0) ? g->_mp_size : -g->_mp_size;
		BN_zero(bn);
		
		if(bn_expand2 (bn, s) == NULL)
			return 0;
		
		bn->top = s;
		memcpy(&bn->d[0], &g->_mp_d[0], s * sizeof(bn->d[0]));
		
		bn_correct_top(bn);
		bn->neg = g->_mp_size >= 0 ? 0 : 1;
		
		return 1;
	}
	else
	{
		int toret;
		char *tmpchar = OPENSSL_malloc(mpz_sizeinbase(g, 16) + 10);
		
		if(!tmpchar) return 0;
			mpz_get_str(tmpchar, 16, g);
		
		toret = BN_hex2bn(&bn, tmpchar);
		OPENSSL_free(tmpchar);
		
		return toret;
	}
}

