import qs2
import ansi

def main():
    total = 2048
    cracked = 0

    for i in range(total):
        crkr = qs2.cracker(input_length=6, methods=qs2.FreqAnalysisMethod.ALL)
        sbox = crkr.crack()

        if sbox != crkr.cipher.sbox:
            print(ansi.red(sbox))
            continue

        # don't waste ALLLLL of our time printing...
        if not i % 5:
            print(sbox, end='\r')

        cracked += 1

    print(f'{ansi.CLEARLINE}Cracked {cracked}/{total}. ({cracked/total*100:.02f}%)')

if __name__ == '__main__':
    main()
