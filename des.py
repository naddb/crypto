def main():
    # Получаем от пользователя текст и ключ
    text = input("\nEnter the message to be encrypted: ")
    key = input("Enter a key of 8 length (characters or numbers only): \n")
    # Если ключ не 64 битный то отмена
    if len(key) != 8:
        print("Invalid key length. Cancelling.")
        return
    # Флаг определяющий подходит ли текст по размеру блока 64 бит
    padding_flag = (len(text) % 8 != 0)
    # Зашифровываем текст с использованием ключа
    encryp_text = Encryption(key, text, padding_flag)
    # Расшифровываем текст с использованием ключа
    decryp_text = Decryption(key, encryp_text, padding_flag)
    # Результат
    print("\nEncrypted text:", encryp_text)
    print("Decrypted text:", decryp_text)
    print()
    

def Encryption(key, text, padding):
    # Зашифровка текста с использованием ключа
    # Проверка на размер текста
    if padding == True:
        paddingLength = 8 - (len(text) % 8)
        # Добавляем нужное количество набивки. Например если не хватает четырех то text4444
        text += str(paddingLength) * paddingLength
    # Шифруем текст используя алгоритм DES
    encryp_text = DES(key, text, padding, True)

    return encryp_text

def Decryption(key, text, padding):
    decryp_text = DES(key, text, padding, False)

    # Обратный процесс, убирание набивки в конце текста
    if padding == True:
        # Смотря на последнюю букву в тексте убираем нужное количество
        return decryp_text[: -(int(decryp_text[-1]))]
    return decryp_text
    
def DES(key, text, padding, encrypt_flag):
    # Получаем лист ключей для каждого раунда
    keys = get_keys(key)

    # Разделяем текст на блоки по 8 байт (64 бит)
    text_8byte_blocks = [text[i : i + 8] for i in range(0, len(text), 8)]
    result = []

    for block in text_8byte_blocks:
        # Переводим 64 битный блок в бинарный вид 
        block = string_2bits(block)
        # Initial permutation
        block = permutation(block, initial_perm_matrix)
        # Делим на левый и правый блок по 32 бита
        l_block, r_block = [block[i : i + 32] for i in range(0, len(block), 32)]

        temp_bits = None

        # 16 раундов
        for i in range(16):
            # Feistel
            # Расширяем правый блок до 48 битов
            exp_r_block = permutation(r_block, exp_matrix)
            
            # Xor расширенного правого блока с subkey
            if encrypt_flag == True: 
                temp_bits = xor(keys[i], exp_r_block)
            elif encrypt_flag == False:
                temp_bits = xor(keys[15 - i], exp_r_block)
            # Sboxes берут определенное бинарное число на входе 
            # и заменяют его на фиксированное другое меньшее бинарное число на выходе
            # тем самым сжимая исходные данные
            temp_bits = Sbox_subst(temp_bits)
            #Permutation
            temp_bits = permutation(temp_bits, perm_matrix)
            temp_bits = xor(l_block, temp_bits)
            # Замена блоков
            l_block = r_block
            r_block = temp_bits

        #Final permutation
        result += permutation(r_block + l_block, final_perm_matrix)
    # Перевод бинарного значения в текст
    return bit_array_2string(result)


def Sbox_subst(bitArray):
    # Делим 48 битный поток чисел на блоки по 6 бит
    blocks = [bitArray[i : i + 6] for i in range(0, len(bitArray), 6)]
    result = []
    # 8 Sboxes
    for i in range(len(blocks)):
        block = blocks[i]
        # Внешние два бита это строка 
        row = int(str(block[0]) + str(block[5]), 2)
        # Внутренние 4 бита это столбец
        column = int(''.join([str(x) for x in block[1:-1]]), 2)
        # При подстановке в таблицу получаем новое 4-х битное значение (в десятичном формате)
        sbox_result = Sboxes[i][row][column]
        # Перевод значения S бокса в бинарное значение
        value_in_binary = val_in_bin(sbox_result, 4)
        # Добавляем готовое 4-х битное значение в результат в формате int
        result += [int(bit) for bit in value_in_binary]

    return result

def string_2bits(text):
    # Перевод текста в массив битов
    bit_array = []
    for letter in text:
        # Получаем 8 битное бинарное значение буквы
        letter_in_binary = val_in_bin(letter, 8)
        # Делаем лист из 8 битов
        binary_letter = [int(x) for x in list(letter_in_binary)]
        # Добавляем в конечный результат 
        bit_array += binary_letter
    return bit_array

def val_in_bin(letter, bit_len):
    # Перевод вводного значения в двоичное значение в виде строки заданного размера
    
    if isinstance(letter, int): # Если letter это число
        value_in_binary = bin(letter)[2:] # [2:] убирает кодировку
    else:                       # Если letter это буква
        value_in_binary = bin(ord(letter))[2:]
    # Если не подходит под заданный размер добавляем нули в начале
    while len(value_in_binary) < bit_len:
        value_in_binary = "0" + value_in_binary
    return value_in_binary

def bit_array_2string(array):
    # Перевод массива битов в текст
    # Делим на блоки по 8 бит (буква всегда размером в 8 бит)
    byte_blocks = [array[i : i + 8] for i in range(0, len(array), 8)]
    byte_string = []
    # Для каждого байта (8 бит)
    for byte in byte_blocks:
        bits = []
        # Для каждого бита в байте
        for bit in byte:
            # Добавляем в строку биты
            bits += str(bit)
        # Добавляем строку в массив
        byte_string.append("".join(bits))
    # Каждую строку переводим в букву и возвращаем
    return "".join([chr(int(str_byte, 2)) for str_byte in byte_string])

def permutation(array, table):
    # Перестановка каждого элемента в фиксированную позицию матрицы
    return [array[element - 1] for element in table]

def xor(list1, list2):
    # Xor листов
    return [a ^ b for a, b in zip(list1,list2)]

def get_keys(key):
    # Генерация ключей
    keys = []
    # Перевод ключа в массив битов
    key = string_2bits(key)
    # Drop parity bits, сжимаем ключ в 56 бит
    key = permutation(key, key_matrix_1)
    # Разделяем ключ на два сабключа по 28 бит
    l_subkey, r_subkey = [key[i : i + 28] for i in range(0, len(key), 28)]
    #16 subkeys
    for i in range(16):
        #Bits rotation 
        l_subkey = l_subkey[(shift[i]):] + l_subkey[:(shift[i])]
        r_subkey = r_subkey[(shift[i]):] + r_subkey[:(shift[i])]
        temp_key = l_subkey + r_subkey
        # Сжимаем до 48 бит и добавляем сабключ в лист
        keys.append(permutation(temp_key, key_matrix_2))

    return keys

perm_matrix = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

final_perm_matrix = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

initial_perm_matrix =[
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

exp_matrix = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

Sboxes = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

key_matrix_1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

key_matrix_2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

if __name__ == '__main__':
    main()