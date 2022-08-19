from collections import Counter
from random import shuffle
from enum import Flag, auto
from time import perf_counter
import numpy as np
import ansi

class FreqAnalysisMethod(Flag):
	SIMPLE = auto() # via character sets of length 1
	COMPLEX = auto() # via character set intersections and differences
	ALL = SIMPLE | COMPLEX

class cipher:
	"""
	An object to represent the Queen Sarah 2 Simple Cipher.
	- alphabet = [a-z_]
	- block size = 3
	- min # rounds = 10

	---
	## Methods

	- alpha_index(c1: str, *c2: str) -> int\n
		Returns the index in the alphabet of this character combination.

	- encrpyt(text: str) -> str\n
		Encrypt the given text.

	- permute(text: str) -> str\n
		Step (2/2) of single-round-encryption.

	- single_round(text: str) -> str\n
		Perform a single round of encryption.
	
	- substitute(text: str) -> str\n
		Step (1/2) of single-round-encryption.
	"""
	def __init__(self, sbox:str=None) -> None:
		# CONSTANTS -- DO NOT MODIFY
		self.alphabet:str	= 'abcdefghijklmnopqrstuvwxyz_'
		self.length:int		= len(self.alphabet)
		self.blocksize:int	= 3

		# Error check user-provided sbox
		if sbox:
			if not isinstance(sbox, str):
				raise AssertionError(ansi.red('sbox must be a \'str\'!'))
			if len(sbox) != self.length:
				raise AssertionError(ansi.red(f'sbox must have a length of {self.length}!'))
			if len(set(sbox)) != self.length:
				raise AssertionError(ansi.red('sbox cannot have duplicates!'))
			if any(char not in self.alphabet for char in sbox):
				raise AssertionError(ansi.red(f'sbox may only contain characters within [{self.alphabet}]!'))
			if sbox == self.alphabet:
				raise AssertionError(ansi.red('sbox must be different than the alphabet!'))
		# Otherwise, generate a random sbox.
		else:
			sbox = self.gen_sbox()
		self.sbox: str = sbox

	def gen_sbox(self) -> str:
		"""
		Generates a random sbox that is guaranteed to be different than the alphabet.
		"""
		sbox = list(self.alphabet)
		while ''.join(sbox) == self.alphabet:
			shuffle(sbox)
		return ''.join(sbox)

	def _sbox_at(self, c1:str, c2:str=None):
		return self.sbox[self.alpha_index(c1, c2)]

	def alpha_index(self, c1:str, c2:str=None) -> int:
		"""
		Returns the index in the alphabet of this character combination.

		---
		## Parameters

		c1 : str
			The first character.

		*c2 : str
			The second character.

		## Returns

		return : int
			The remainder of the sum of the indecies of `c1` and `c2` in the alphabet.
		"""
		if c2:
			return (self.alphabet.index(c1) + self.alphabet.index(c2)) % self.length
		return self.alphabet.index(c1)

	def substitute(self, text:str) -> str:
		"""
		### Step (1/2) of single-round-encryption.\n
		Replace each character in `text` with a character from the sbox based on it's
		left-neighboring character and their positions in the alphabet. Since the first
		character of `text` has no left neighbor, the substitution is based ONLY on
		said character.\n
		Scroll down to Procedure for more details.

		---
		## Parameters

		text : str
			The string on which substitution will be performed.

		## Returns

		running_sub : str
			The string of substituted characters.

		---
		## Procedure

		Let A be the cipher's alphabet.\n
		sub[i] =\n
			sbox[ A.index( text[i] ) ], i==0\n
			sbox[ (A.index( text[i] ) + A.index( text[i-1] )) % len(A) ], otherwise
		"""
		return self._sbox_at(text[0]) + ''.join(
			self._sbox_at(text[i-1], text[i])
				for i in range(1, len(text)) )

	def permute(self, text:str) -> str:
		"""
		### Step (2/2) of single-round-encryption.\n
		Procedurally rearranges the characters based on `blocksize`.\n
		Scroll down to Procedure for more details.

		---
		## Parameters

		text : str
			The string to permute.

		## Returns

		return : str
			The permuted string.

		---
		## Procedure

		Starting at index `blocksize-1`, append every `blocksize`th character to a new secondary
		string until the end of the primary string. Do this `blocksize` times total, where the
		starting index is incremented by one and modded by `blocksize` before each additional step.
		"""
		return ''.join(
			text[(self.blocksize + i - 1) % self.blocksize :: self.blocksize]
				for i in range(self.blocksize) )

	def unpermute(self, text: str) -> 'list[str]':
		"""
		Undoes the permutation step that occurs every round of encryption.
		This is used when generating the relationship table.

		---
		## Parameters

		text : str
			The string to un-permute.

		## Returns

		return : list[str]
			The un-permuted string as a list of characters.
		"""
		# num blocks
		length = len(text)
		nb = length // self.blocksize
		return list(text[j % length]
				for i in range(nb)
					for j in range(nb + i, length + nb, nb))

	def single_round(self, text:str) -> str:
		"""
		Perform a single round of encryption.

		---
		## Parameters

		text : str
			The string to apply a single round on.

		## Returns

		text : str
			The text, after applying a single round of encryption.
		"""
		return self.permute(self.substitute(text))

	def encrypt(self, text:str) -> str:
		"""
		Encrypt the given text. The minimum number of rounds is 10.\n
		Potentially pads the text before encryting.

		---
		## Parameters

		text : str
			The string to encrypt.

		## Returns

		ciphertext : str
			The encrypted text.
		"""
		# Pad text if necessary
		remainder = len(text) % self.blocksize
		if remainder:
			text += '_' * (self.blocksize - remainder)

		for _ in range( max(10, len(text)) ):
			text = self.single_round(text)
		return text

class cracker:
	class __stats:
		def __init__(self, parent) -> None:
			self.parent: cracker = parent
			self.time:float	= 0.0
			self.num_sets_compared_simple:int = 0
			self.num_simple_mappings:int = 0
			self.num_sets_compared_complex:int = 0
			self.num_intersections_mappings:int = 0
			self.num_differences_mappings:int = 0
			self.num_trail_mappings:int = 0

		def __repr__(self) -> str:
			return f'''########################################
{str(self.parent.methods).center(40)}
########################################
 Method  | Total Sets |     Mapping
  Type   |  Compared  |   Types Found
========================================
  Trail  |            {self.num_trail_mappings}
----------------------------------------
 Simple  |{str(self.num_sets_compared_simple).center(12)}|{str(self.num_simple_mappings).center(17)}
----------------------------------------
 Complex |{str(self.num_intersections_mappings).center(12)}| {self.num_intersections_mappings} intersection
         |            |  {self.num_differences_mappings} difference
########################################
Runtime: {self.time*1000:.03f} milliseconds'''

	def __init__(self, sbox:str=None, input_length:int=9, methods:FreqAnalysisMethod=FreqAnalysisMethod.SIMPLE) -> None:
		self.methods:FreqAnalysisMethod	= methods
		self.cipher:cipher					= cipher(sbox=sbox)
		self.sbox:list[str]				= ['.'] * self.cipher.length
		self.remaining:list[str]		= list(self.cipher.alphabet)
		self.stats: cracker.__stats		= self.__stats(self)

		# Correct the user-provided text length, if necessary
		rem = input_length % self.cipher.blocksize
		if rem:
			input_length -= rem
			print(ansi.yellow(f'*WARNING*: The provided plaintext length is not a multiple of QS2\'s\
				blocksize, {self.cipher.blocksize}. A value of {input_length} will be used instead.'))
		self.input_length:int = input_length

		# Relationship table and frequency dictionary
		# (to be generated later for timing purposes)
		self.rtable:np.ndarray = None
		self.freqs:dict[int, list[tuple[set]]] = None
	
	def _gen_relationship_table(self) -> np.ndarray:
		rtable: np.ndarray = np.zeros((self.cipher.length, self.input_length * 2), dtype=str)
		for row, char in enumerate(self.cipher.alphabet):
			ptxt0 = (char + self.cipher.alphabet[0]) * (self.input_length // 2) + (char if self.input_length % 2 else '')
			ptxt1 = char * self.input_length
			ctxt0 = self.cipher.encrypt(ptxt0)
			ctxt1 = self.cipher.encrypt(ptxt1)

			rtable[row] = list(ctxt0[0])\
			+ list(self.alphabet_at(ctxt0[j-1], ctxt0[j]) for j in range(1, self.input_length))\
			+ self.cipher.unpermute(ctxt1)

		return rtable

	def _gen_frequency_dict(self) -> 'dict[int, list[tuple[set]]]':
		if not isinstance(self.rtable, np.ndarray):
			raise AssertionError('The relationship table is required to generate the frequency table.')

		# Create a frequency dict for each column
		col_freqs: list[dict[int, set]] = []
		for col in range(self.input_length * 2):
			d: dict[int, set] = {}
			for k,v in Counter(self.rtable[:,col]).most_common():
				try: d[v].add(k)
				except KeyError: d[v] = set(k)
			col_freqs.append(d)
		
		# Merge into unified dict
		freqs: dict[int, list[tuple[set]]] = {}
		for i in range(self.input_length):
			for (freq, set1), set2 in zip(col_freqs[i].items(), col_freqs[i + self.input_length].values()):
				setmap = (set1, set2)
				try: freqs[freq].append(setmap)
				except KeyError: freqs[freq] = [setmap]
		return freqs

	def _remove_from_freqs(self, c1:str, c2:str) -> None:
		for freq, setmap in self.freqs.items():
			for i, (chars_in, chars_out) in enumerate(setmap):
				chars_in.discard(c1)
				chars_out.discard(c2)
				if not chars_in:
					self.freqs[freq].pop(i)
					self._remove_from_freqs(c1, c2)
					return

			if not setmap:
				self.freqs.pop(freq)
				self._remove_from_freqs(c1, c2)
				return

	def _add_mapping(self, c1:str, c2:str) -> bool:
		# Add new mapping to our sbox, remove all occurences of this mapping from the
		# frequency table, and remove c1 from the list of remaining unmapped characters.
		self.sbox[self.cipher.alpha_index(c1)] = c2
		self._remove_from_freqs(c1, c2)
		self.remaining.remove(c1)

		# return if all letters successfully mapped
		if not self.remaining:
			return
		# final mapping
		elif len(self.remaining) == 1:
			self._add_mapping(self.remaining[0], (set(self.cipher.alphabet) - set(self.sbox)).pop())

		# Follow trail of new mappings.
		chars_in = self.rtable[self.cipher.alpha_index(c1), :self.input_length]
		chars_out = self.rtable[self.cipher.alpha_index(c2), self.input_length:]
		for cin, cout in zip(chars_in, chars_out):
			if self.sbox_at(cin) == '.':
				self._add_mapping(cin, cout)
				self.stats.num_trail_mappings += 1

		self.analyze_frequencies()
		return

	def analyze_frequencies(self) -> None:

		# One-to-One mappings (Default/Always)
		if self.methods & FreqAnalysisMethod.SIMPLE:
			for setmap in self.freqs.values():
				for chars_in, chars_out in setmap:
					self.stats.num_sets_compared_simple += 1
					if len(chars_in) == 1:
						self._add_mapping(chars_in.pop(), chars_out.pop())
						self.stats.num_simple_mappings += 1
						return

		# Intersections and Differences (Full)
		if self.methods & FreqAnalysisMethod.COMPLEX:
			for freq1, charmaps1 in self.freqs.items():
				for i, (set1_in, set1_out) in enumerate(charmaps1):
					for freq_inner, charmaps_inner in self.freqs.items():
						for j, (set2_in, set2_out) in enumerate(charmaps_inner):
							if freq1 != freq_inner and i != j:	# Don't compare to self
								self.stats.num_sets_compared_complex += 1

								# Intersection
								intx = set1_in & set2_in
								if len(intx) == 1:
									self._add_mapping(intx.pop(), (set1_out & set2_out).pop())
									self.stats.num_intersections_mappings += 1
									return

								# Difference
								diff = set1_in - set2_in
								if len(diff) == 1:
									self._add_mapping(diff.pop(), (set1_out - set2_out).pop())
									self.stats.num_differences_mappings += 1
									return

		return

	def alphabet_at(self, c1:str, c2:str=None):
		return self.cipher.alphabet[self.cipher.alpha_index(c1, c2)]

	def sbox_at(self, c1:str, c2:str=None):
		return self.sbox[self.cipher.alpha_index(c1, c2)]

	def crack(self) -> str:
		beg = perf_counter()
		self.rtable = self._gen_relationship_table()
		self.freqs = self._gen_frequency_dict()
		self.analyze_frequencies()
		end = perf_counter()
		self.stats.time = end - beg
		return ''.join(self.sbox)

def analyze():
	methods = (FreqAnalysisMethod.SIMPLE, FreqAnalysisMethod.COMPLEX, FreqAnalysisMethod.ALL)
	input_lengths = (3,6,9,12,15)
	rng = 1000
	print(rng, 'trials each:')
	for m in methods:
		print(m)
		for il in input_lengths:
			print(f'input length = {il}')
			succ = 0
			total = 0.0
			for _ in range(rng):
				c = cracker(input_length=il, methods=m)
				if c.crack() == c.cipher.sbox:
					succ += 1
					total += c.stats.time
			print(f'\tsuccess rate = {succ/rng*100:.02f}%')
			print(f'\tavg time = {total/succ*1000:.03f} ms')
