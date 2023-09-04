#pragma once

#include <iostream>
#include <cmath>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <sstream>
#include <msclr\marshal_cppstd.h>
#include <msclr\marshal.h>

namespace ProjectCipher
{
#define COUNT_MAX_ARRAY 40000 // верхний предел чисел для поиска простых чисел

	// переменные для RSA
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::IO;
	using namespace System::Text;

	// переменные для RSA
	int n, open_exponent = 0, d;
	long PrimeNumbersArray[COUNT_MAX_ARRAY]; // массив простых чисел
	int* arrPrimeNumber;
	int countPrimeN; // кол-во простых чисел
	int Plaintext[100]; // Открытый текст
	long long Ciphertext[100]; // Зашифрованный текст

	// переменные для Вижинера
	int table[26][52];
	char filename_viginer[] = "PlainText.txt";
	char key_viginer[] = "techierfefr";

	/// <summary>
	/// Сводка для MainForm
	/// </summary>
	public ref class MainForm : public System::Windows::Forms::Form
	{
		public:
		MainForm(void)
		{
			InitializeComponent();

			//Рассчитываю ключи для шифрования RSA
			RSA_Initialize();
			radioButton_array->Checked = true; // радиокнопка для операции с массивом по умолчанию
			label_FileNameRSA->Text = "";
			label_filename->Text = "";
			label_name_file_Pleif->Text = "";

			msclr::interop::marshal_context context;
			textBox_key_Viginer->Text = context.marshal_as<System::String^>(key_viginer);
		}

		protected:
		/// <summary>
		/// Освободить все используемые ресурсы.
		/// </summary>
		~MainForm()
		{
			if (components)
			{
				delete components;
			}
		}
		private: System::Windows::Forms::TabControl^ tabControl1;
		private: System::Windows::Forms::TabPage^ tabPage_RSA;
		private: System::Windows::Forms::TabPage^ tabPage_Vijiner;
		protected:


		private: System::Windows::Forms::Button^ button_Close;
		private: System::Windows::Forms::TabPage^ tabPage_Pleifer;

		private: System::Windows::Forms::Button^ button1;
		private: System::Windows::Forms::Button^ button_Clear;
		private: System::Windows::Forms::Label^ label_DecryptedText;

		private: System::Windows::Forms::TextBox^ textBox_NumbersDecrypt;
		private: System::Windows::Forms::Label^ label_CipherText;



		private: System::Windows::Forms::TextBox^ textBox_NumbersEncrypt;
		private: System::Windows::Forms::Label^ label_PlainText;


		private: System::Windows::Forms::TextBox^ textBox_Numbers;


		private: System::Windows::Forms::Button^ button_clear_Pleif;
		private: System::Windows::Forms::TextBox^ textBox_Pleif_Decoded;
		private: System::Windows::Forms::Label^ label13;
		private: System::Windows::Forms::TextBox^ textBox_Pleif_Encoded;
		private: System::Windows::Forms::Label^ label12;
		private: System::Windows::Forms::TextBox^ textBox_Pleif_Mess;
		private: System::Windows::Forms::Label^ label11;
		private: System::Windows::Forms::TextBox^ textBox_Pleif_key;
		private: System::Windows::Forms::Label^ label10;
		private: System::Windows::Forms::Button^ button_Viginer;

		private: System::Windows::Forms::OpenFileDialog^ openFileDialog_ToCipher;

		private: System::Windows::Forms::TextBox^ textBox_key_Viginer;
		private: System::Windows::Forms::Label^ label15;
		private: System::Windows::Forms::Button^ button_Open_File;
		private: System::Windows::Forms::Label^ label_filename;
		private: System::Windows::Forms::TextBox^ textBox_from_File;

		private: System::Windows::Forms::Label^ label_FileNameRSA;

		private: System::Windows::Forms::GroupBox^ groupBox_pq;
		private: System::Windows::Forms::GroupBox^ groupBox_Exp;
		private: System::Windows::Forms::TextBox^ textBox_dPrivate;
		private: System::Windows::Forms::TextBox^ textBox_ePublic;
		private: System::Windows::Forms::Label^ label6;
		private: System::Windows::Forms::Label^ label5;
		private: System::Windows::Forms::GroupBox^ groupBox1;
		private: System::Windows::Forms::TextBox^ textBox_Ailer;
		private: System::Windows::Forms::Label^ label4;
		private: System::Windows::Forms::TextBox^ textBox_n;
		private: System::Windows::Forms::Label^ label3;
		private: System::Windows::Forms::TextBox^ textBox_qPrime;
		private: System::Windows::Forms::TextBox^ textBox_pPrime;
		private: System::Windows::Forms::Label^ label2;
		private: System::Windows::Forms::Label^ label1;
		private: System::Windows::Forms::GroupBox^ groupBox2;
		private: System::Windows::Forms::Label^ label_private_key;
		private: System::Windows::Forms::Label^ label_public_key;
		private: System::Windows::Forms::Button^ button_enc_decr;
		private: System::Windows::Forms::GroupBox^ groupBox3;
		private: System::Windows::Forms::RadioButton^ radioButton_file;
		private: System::Windows::Forms::RadioButton^ radioButton_array;
		private: System::Windows::Forms::Button^ button_ReadDecryptText;
		private: System::Windows::Forms::Label^ label9;
		private: System::Windows::Forms::TextBox^ textBox_TextDencrypt;
		private: System::Windows::Forms::Label^ label8;
		private: System::Windows::Forms::TextBox^ textBox_TextEncrypt;
		private: System::Windows::Forms::Label^ label7;
		private: System::Windows::Forms::Button^ button_clear_Viginer;
		private: System::Windows::Forms::Button^ button_Pleifer_enc_dec;
		private: System::Windows::Forms::Label^ label_name_file_Pleif;
		private: System::Windows::Forms::Button^ button_open_file_Pleifer;
	private: System::Windows::Forms::Label^ label16;
		private: System::Windows::Forms::Label^ label14;


		private:
		/// <summary>
		/// Обязательная переменная конструктора.
		/// </summary>
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Требуемый метод для поддержки конструктора — не изменяйте 
		/// содержимое этого метода с помощью редактора кода.
		/// </summary>
		void InitializeComponent(void)
		{
			this->tabControl1 = (gcnew System::Windows::Forms::TabControl());
			this->tabPage_RSA = (gcnew System::Windows::Forms::TabPage());
			this->button_ReadDecryptText = (gcnew System::Windows::Forms::Button());
			this->groupBox3 = (gcnew System::Windows::Forms::GroupBox());
			this->radioButton_file = (gcnew System::Windows::Forms::RadioButton());
			this->radioButton_array = (gcnew System::Windows::Forms::RadioButton());
			this->button_enc_decr = (gcnew System::Windows::Forms::Button());
			this->groupBox2 = (gcnew System::Windows::Forms::GroupBox());
			this->label_private_key = (gcnew System::Windows::Forms::Label());
			this->label_public_key = (gcnew System::Windows::Forms::Label());
			this->groupBox_Exp = (gcnew System::Windows::Forms::GroupBox());
			this->textBox_dPrivate = (gcnew System::Windows::Forms::TextBox());
			this->textBox_ePublic = (gcnew System::Windows::Forms::TextBox());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->textBox_Ailer = (gcnew System::Windows::Forms::TextBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->textBox_n = (gcnew System::Windows::Forms::TextBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->groupBox_pq = (gcnew System::Windows::Forms::GroupBox());
			this->textBox_qPrime = (gcnew System::Windows::Forms::TextBox());
			this->textBox_pPrime = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label_FileNameRSA = (gcnew System::Windows::Forms::Label());
			this->label_DecryptedText = (gcnew System::Windows::Forms::Label());
			this->textBox_NumbersDecrypt = (gcnew System::Windows::Forms::TextBox());
			this->label_CipherText = (gcnew System::Windows::Forms::Label());
			this->textBox_NumbersEncrypt = (gcnew System::Windows::Forms::TextBox());
			this->label_PlainText = (gcnew System::Windows::Forms::Label());
			this->textBox_Numbers = (gcnew System::Windows::Forms::TextBox());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->button_Clear = (gcnew System::Windows::Forms::Button());
			this->tabPage_Vijiner = (gcnew System::Windows::Forms::TabPage());
			this->button_clear_Viginer = (gcnew System::Windows::Forms::Button());
			this->label9 = (gcnew System::Windows::Forms::Label());
			this->textBox_TextDencrypt = (gcnew System::Windows::Forms::TextBox());
			this->label8 = (gcnew System::Windows::Forms::Label());
			this->textBox_TextEncrypt = (gcnew System::Windows::Forms::TextBox());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->textBox_from_File = (gcnew System::Windows::Forms::TextBox());
			this->label_filename = (gcnew System::Windows::Forms::Label());
			this->button_Open_File = (gcnew System::Windows::Forms::Button());
			this->textBox_key_Viginer = (gcnew System::Windows::Forms::TextBox());
			this->label15 = (gcnew System::Windows::Forms::Label());
			this->button_Viginer = (gcnew System::Windows::Forms::Button());
			this->tabPage_Pleifer = (gcnew System::Windows::Forms::TabPage());
			this->label_name_file_Pleif = (gcnew System::Windows::Forms::Label());
			this->button_open_file_Pleifer = (gcnew System::Windows::Forms::Button());
			this->button_Pleifer_enc_dec = (gcnew System::Windows::Forms::Button());
			this->button_clear_Pleif = (gcnew System::Windows::Forms::Button());
			this->textBox_Pleif_Decoded = (gcnew System::Windows::Forms::TextBox());
			this->label13 = (gcnew System::Windows::Forms::Label());
			this->textBox_Pleif_Encoded = (gcnew System::Windows::Forms::TextBox());
			this->label12 = (gcnew System::Windows::Forms::Label());
			this->textBox_Pleif_Mess = (gcnew System::Windows::Forms::TextBox());
			this->label11 = (gcnew System::Windows::Forms::Label());
			this->textBox_Pleif_key = (gcnew System::Windows::Forms::TextBox());
			this->label10 = (gcnew System::Windows::Forms::Label());
			this->button_Close = (gcnew System::Windows::Forms::Button());
			this->openFileDialog_ToCipher = (gcnew System::Windows::Forms::OpenFileDialog());
			this->label14 = (gcnew System::Windows::Forms::Label());
			this->label16 = (gcnew System::Windows::Forms::Label());
			this->tabControl1->SuspendLayout();
			this->tabPage_RSA->SuspendLayout();
			this->groupBox3->SuspendLayout();
			this->groupBox2->SuspendLayout();
			this->groupBox_Exp->SuspendLayout();
			this->groupBox1->SuspendLayout();
			this->groupBox_pq->SuspendLayout();
			this->tabPage_Vijiner->SuspendLayout();
			this->tabPage_Pleifer->SuspendLayout();
			this->SuspendLayout();
			// 
			// tabControl1
			// 
			this->tabControl1->Controls->Add(this->tabPage_RSA);
			this->tabControl1->Controls->Add(this->tabPage_Vijiner);
			this->tabControl1->Controls->Add(this->tabPage_Pleifer);
			this->tabControl1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->tabControl1->Location = System::Drawing::Point(12, 12);
			this->tabControl1->Name = L"tabControl1";
			this->tabControl1->SelectedIndex = 0;
			this->tabControl1->Size = System::Drawing::Size(960, 636);
			this->tabControl1->TabIndex = 0;
			// 
			// tabPage_RSA
			// 
			this->tabPage_RSA->Controls->Add(this->button_ReadDecryptText);
			this->tabPage_RSA->Controls->Add(this->groupBox3);
			this->tabPage_RSA->Controls->Add(this->button_enc_decr);
			this->tabPage_RSA->Controls->Add(this->groupBox2);
			this->tabPage_RSA->Controls->Add(this->groupBox_Exp);
			this->tabPage_RSA->Controls->Add(this->groupBox1);
			this->tabPage_RSA->Controls->Add(this->groupBox_pq);
			this->tabPage_RSA->Controls->Add(this->label_FileNameRSA);
			this->tabPage_RSA->Controls->Add(this->label_DecryptedText);
			this->tabPage_RSA->Controls->Add(this->textBox_NumbersDecrypt);
			this->tabPage_RSA->Controls->Add(this->label_CipherText);
			this->tabPage_RSA->Controls->Add(this->textBox_NumbersEncrypt);
			this->tabPage_RSA->Controls->Add(this->label_PlainText);
			this->tabPage_RSA->Controls->Add(this->textBox_Numbers);
			this->tabPage_RSA->Controls->Add(this->button1);
			this->tabPage_RSA->Controls->Add(this->button_Clear);
			this->tabPage_RSA->Location = System::Drawing::Point(4, 25);
			this->tabPage_RSA->Name = L"tabPage_RSA";
			this->tabPage_RSA->Padding = System::Windows::Forms::Padding(3);
			this->tabPage_RSA->Size = System::Drawing::Size(952, 607);
			this->tabPage_RSA->TabIndex = 0;
			this->tabPage_RSA->Text = L"Алгоритм асимметричного шифрования RSA";
			this->tabPage_RSA->UseVisualStyleBackColor = true;
			// 
			// button_ReadDecryptText
			// 
			this->button_ReadDecryptText->Location = System::Drawing::Point(749, 518);
			this->button_ReadDecryptText->Name = L"button_ReadDecryptText";
			this->button_ReadDecryptText->Size = System::Drawing::Size(176, 75);
			this->button_ReadDecryptText->TabIndex = 29;
			this->button_ReadDecryptText->Text = L"Прочитать расшифрованный файл";
			this->button_ReadDecryptText->UseVisualStyleBackColor = true;
			this->button_ReadDecryptText->Visible = false;
			this->button_ReadDecryptText->Click += gcnew System::EventHandler(this, &MainForm::button_ReadDecryptText_Click);
			// 
			// groupBox3
			// 
			this->groupBox3->Controls->Add(this->radioButton_file);
			this->groupBox3->Controls->Add(this->radioButton_array);
			this->groupBox3->Location = System::Drawing::Point(20, 235);
			this->groupBox3->Name = L"groupBox3";
			this->groupBox3->Size = System::Drawing::Size(694, 59);
			this->groupBox3->TabIndex = 28;
			this->groupBox3->TabStop = false;
			this->groupBox3->Text = L"Выбор объекта шифрования / дешифрования";
			// 
			// radioButton_file
			// 
			this->radioButton_file->AutoSize = true;
			this->radioButton_file->Location = System::Drawing::Point(315, 21);
			this->radioButton_file->Name = L"radioButton_file";
			this->radioButton_file->Size = System::Drawing::Size(135, 20);
			this->radioButton_file->TabIndex = 1;
			this->radioButton_file->TabStop = true;
			this->radioButton_file->Text = L"Текстовый файл";
			this->radioButton_file->UseVisualStyleBackColor = true;
			this->radioButton_file->CheckedChanged += gcnew System::EventHandler(this, &MainForm::radioButton_file_CheckedChanged);
			// 
			// radioButton_array
			// 
			this->radioButton_array->AutoSize = true;
			this->radioButton_array->Location = System::Drawing::Point(12, 21);
			this->radioButton_array->Name = L"radioButton_array";
			this->radioButton_array->Size = System::Drawing::Size(190, 20);
			this->radioButton_array->TabIndex = 0;
			this->radioButton_array->TabStop = true;
			this->radioButton_array->Text = L"Массив случайных чисел";
			this->radioButton_array->UseVisualStyleBackColor = true;
			this->radioButton_array->CheckedChanged += gcnew System::EventHandler(this, &MainForm::radioButton_array_CheckedChanged);
			// 
			// button_enc_decr
			// 
			this->button_enc_decr->Location = System::Drawing::Point(748, 356);
			this->button_enc_decr->Name = L"button_enc_decr";
			this->button_enc_decr->Size = System::Drawing::Size(177, 75);
			this->button_enc_decr->TabIndex = 27;
			this->button_enc_decr->Text = L"Шифровать / Дешифровать массив случайных чисел";
			this->button_enc_decr->UseVisualStyleBackColor = true;
			this->button_enc_decr->Click += gcnew System::EventHandler(this, &MainForm::button_enc_decr_Click);
			// 
			// groupBox2
			// 
			this->groupBox2->Controls->Add(this->label_private_key);
			this->groupBox2->Controls->Add(this->label_public_key);
			this->groupBox2->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->groupBox2->Location = System::Drawing::Point(335, 134);
			this->groupBox2->Name = L"groupBox2";
			this->groupBox2->Size = System::Drawing::Size(379, 86);
			this->groupBox2->TabIndex = 26;
			this->groupBox2->TabStop = false;
			this->groupBox2->Text = L"Ключи";
			// 
			// label_private_key
			// 
			this->label_private_key->AutoSize = true;
			this->label_private_key->Location = System::Drawing::Point(14, 47);
			this->label_private_key->Name = L"label_private_key";
			this->label_private_key->Size = System::Drawing::Size(89, 16);
			this->label_private_key->TabIndex = 1;
			this->label_private_key->Text = L"Секретный";
			// 
			// label_public_key
			// 
			this->label_public_key->AutoSize = true;
			this->label_public_key->Location = System::Drawing::Point(14, 21);
			this->label_public_key->Name = L"label_public_key";
			this->label_public_key->Size = System::Drawing::Size(81, 16);
			this->label_public_key->TabIndex = 0;
			this->label_public_key->Text = L"Открытый";
			// 
			// groupBox_Exp
			// 
			this->groupBox_Exp->Controls->Add(this->textBox_dPrivate);
			this->groupBox_Exp->Controls->Add(this->textBox_ePublic);
			this->groupBox_Exp->Controls->Add(this->label6);
			this->groupBox_Exp->Controls->Add(this->label5);
			this->groupBox_Exp->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->groupBox_Exp->Location = System::Drawing::Point(20, 130);
			this->groupBox_Exp->Name = L"groupBox_Exp";
			this->groupBox_Exp->Size = System::Drawing::Size(295, 90);
			this->groupBox_Exp->TabIndex = 25;
			this->groupBox_Exp->TabStop = false;
			this->groupBox_Exp->Text = L"Экспоненты";
			// 
			// textBox_dPrivate
			// 
			this->textBox_dPrivate->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->textBox_dPrivate->Location = System::Drawing::Point(100, 48);
			this->textBox_dPrivate->Name = L"textBox_dPrivate";
			this->textBox_dPrivate->ReadOnly = true;
			this->textBox_dPrivate->Size = System::Drawing::Size(184, 22);
			this->textBox_dPrivate->TabIndex = 15;
			// 
			// textBox_ePublic
			// 
			this->textBox_ePublic->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->textBox_ePublic->Location = System::Drawing::Point(100, 22);
			this->textBox_ePublic->Name = L"textBox_ePublic";
			this->textBox_ePublic->ReadOnly = true;
			this->textBox_ePublic->Size = System::Drawing::Size(184, 22);
			this->textBox_ePublic->TabIndex = 14;
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->label6->Location = System::Drawing::Point(9, 51);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(79, 16);
			this->label6->TabIndex = 13;
			this->label6->Text = L"d (private)";
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->label5->Location = System::Drawing::Point(9, 25);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(73, 16);
			this->label5->TabIndex = 12;
			this->label5->Text = L"e (public)";
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->textBox_Ailer);
			this->groupBox1->Controls->Add(this->label4);
			this->groupBox1->Controls->Add(this->textBox_n);
			this->groupBox1->Controls->Add(this->label3);
			this->groupBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->groupBox1->Location = System::Drawing::Point(333, 20);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(381, 100);
			this->groupBox1->TabIndex = 24;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = L"Расчетные величины";
			// 
			// textBox_Ailer
			// 
			this->textBox_Ailer->Location = System::Drawing::Point(99, 56);
			this->textBox_Ailer->Name = L"textBox_Ailer";
			this->textBox_Ailer->ReadOnly = true;
			this->textBox_Ailer->Size = System::Drawing::Size(263, 22);
			this->textBox_Ailer->TabIndex = 12;
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(16, 59);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(78, 16);
			this->label4->TabIndex = 11;
			this->label4->Text = L"(p-1)*(q-1)";
			// 
			// textBox_n
			// 
			this->textBox_n->Location = System::Drawing::Point(99, 30);
			this->textBox_n->Name = L"textBox_n";
			this->textBox_n->ReadOnly = true;
			this->textBox_n->Size = System::Drawing::Size(263, 22);
			this->textBox_n->TabIndex = 10;
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(19, 33);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(64, 16);
			this->label3->TabIndex = 9;
			this->label3->Text = L"n = p * q";
			// 
			// groupBox_pq
			// 
			this->groupBox_pq->Controls->Add(this->textBox_qPrime);
			this->groupBox_pq->Controls->Add(this->textBox_pPrime);
			this->groupBox_pq->Controls->Add(this->label2);
			this->groupBox_pq->Controls->Add(this->label1);
			this->groupBox_pq->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->groupBox_pq->Location = System::Drawing::Point(20, 20);
			this->groupBox_pq->Name = L"groupBox_pq";
			this->groupBox_pq->Size = System::Drawing::Size(291, 104);
			this->groupBox_pq->TabIndex = 23;
			this->groupBox_pq->TabStop = false;
			this->groupBox_pq->Text = L"Простые числа";
			// 
			// textBox_qPrime
			// 
			this->textBox_qPrime->Location = System::Drawing::Point(102, 59);
			this->textBox_qPrime->Name = L"textBox_qPrime";
			this->textBox_qPrime->ReadOnly = true;
			this->textBox_qPrime->Size = System::Drawing::Size(184, 22);
			this->textBox_qPrime->TabIndex = 11;
			// 
			// textBox_pPrime
			// 
			this->textBox_pPrime->Location = System::Drawing::Point(102, 33);
			this->textBox_pPrime->Name = L"textBox_pPrime";
			this->textBox_pPrime->ReadOnly = true;
			this->textBox_pPrime->Size = System::Drawing::Size(184, 22);
			this->textBox_pPrime->TabIndex = 10;
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(9, 62);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(92, 16);
			this->label2->TabIndex = 9;
			this->label2->Text = L"q (простое)";
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(9, 36);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(92, 16);
			this->label1->TabIndex = 8;
			this->label1->Text = L"p (простое)";
			// 
			// label_FileNameRSA
			// 
			this->label_FileNameRSA->AutoSize = true;
			this->label_FileNameRSA->Location = System::Drawing::Point(17, 308);
			this->label_FileNameRSA->Name = L"label_FileNameRSA";
			this->label_FileNameRSA->Size = System::Drawing::Size(155, 16);
			this->label_FileNameRSA->TabIndex = 21;
			this->label_FileNameRSA->Text = L"Файл для шифрования";
			// 
			// label_DecryptedText
			// 
			this->label_DecryptedText->AutoSize = true;
			this->label_DecryptedText->Location = System::Drawing::Point(17, 521);
			this->label_DecryptedText->Name = L"label_DecryptedText";
			this->label_DecryptedText->Size = System::Drawing::Size(167, 16);
			this->label_DecryptedText->TabIndex = 19;
			this->label_DecryptedText->Text = L"Расшифрованные числа";
			// 
			// textBox_NumbersDecrypt
			// 
			this->textBox_NumbersDecrypt->Location = System::Drawing::Point(199, 518);
			this->textBox_NumbersDecrypt->Multiline = true;
			this->textBox_NumbersDecrypt->Name = L"textBox_NumbersDecrypt";
			this->textBox_NumbersDecrypt->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_NumbersDecrypt->Size = System::Drawing::Size(515, 75);
			this->textBox_NumbersDecrypt->TabIndex = 18;
			// 
			// label_CipherText
			// 
			this->label_CipherText->AutoSize = true;
			this->label_CipherText->Location = System::Drawing::Point(17, 440);
			this->label_CipherText->Name = L"label_CipherText";
			this->label_CipherText->Size = System::Drawing::Size(160, 16);
			this->label_CipherText->TabIndex = 17;
			this->label_CipherText->Text = L"Зашифрованные числа";
			// 
			// textBox_NumbersEncrypt
			// 
			this->textBox_NumbersEncrypt->Location = System::Drawing::Point(199, 437);
			this->textBox_NumbersEncrypt->Multiline = true;
			this->textBox_NumbersEncrypt->Name = L"textBox_NumbersEncrypt";
			this->textBox_NumbersEncrypt->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_NumbersEncrypt->Size = System::Drawing::Size(515, 75);
			this->textBox_NumbersEncrypt->TabIndex = 16;
			// 
			// label_PlainText
			// 
			this->label_PlainText->AutoSize = true;
			this->label_PlainText->Location = System::Drawing::Point(17, 359);
			this->label_PlainText->Name = L"label_PlainText";
			this->label_PlainText->Size = System::Drawing::Size(160, 16);
			this->label_PlainText->TabIndex = 15;
			this->label_PlainText->Text = L"Числа для шифрования";
			// 
			// textBox_Numbers
			// 
			this->textBox_Numbers->Location = System::Drawing::Point(199, 356);
			this->textBox_Numbers->Multiline = true;
			this->textBox_Numbers->Name = L"textBox_Numbers";
			this->textBox_Numbers->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_Numbers->Size = System::Drawing::Size(515, 75);
			this->textBox_Numbers->TabIndex = 14;
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(748, 24);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(177, 196);
			this->button1->TabIndex = 13;
			this->button1->Text = L"Расчитать новые ключи для шифрования / дешифрования";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &MainForm::button1_Click);
			// 
			// button_Clear
			// 
			this->button_Clear->Location = System::Drawing::Point(748, 235);
			this->button_Clear->Name = L"button_Clear";
			this->button_Clear->Size = System::Drawing::Size(177, 59);
			this->button_Clear->TabIndex = 12;
			this->button_Clear->Text = L"Очистить поля";
			this->button_Clear->UseVisualStyleBackColor = true;
			this->button_Clear->Click += gcnew System::EventHandler(this, &MainForm::button_Clear_Click);
			// 
			// tabPage_Vijiner
			// 
			this->tabPage_Vijiner->Controls->Add(this->label16);
			this->tabPage_Vijiner->Controls->Add(this->button_clear_Viginer);
			this->tabPage_Vijiner->Controls->Add(this->label9);
			this->tabPage_Vijiner->Controls->Add(this->textBox_TextDencrypt);
			this->tabPage_Vijiner->Controls->Add(this->label8);
			this->tabPage_Vijiner->Controls->Add(this->textBox_TextEncrypt);
			this->tabPage_Vijiner->Controls->Add(this->label7);
			this->tabPage_Vijiner->Controls->Add(this->textBox_from_File);
			this->tabPage_Vijiner->Controls->Add(this->label_filename);
			this->tabPage_Vijiner->Controls->Add(this->button_Open_File);
			this->tabPage_Vijiner->Controls->Add(this->textBox_key_Viginer);
			this->tabPage_Vijiner->Controls->Add(this->label15);
			this->tabPage_Vijiner->Controls->Add(this->button_Viginer);
			this->tabPage_Vijiner->Location = System::Drawing::Point(4, 25);
			this->tabPage_Vijiner->Name = L"tabPage_Vijiner";
			this->tabPage_Vijiner->Padding = System::Windows::Forms::Padding(3);
			this->tabPage_Vijiner->Size = System::Drawing::Size(952, 607);
			this->tabPage_Vijiner->TabIndex = 1;
			this->tabPage_Vijiner->Text = L"Шифр Вижинера";
			this->tabPage_Vijiner->UseVisualStyleBackColor = true;
			// 
			// button_clear_Viginer
			// 
			this->button_clear_Viginer->Location = System::Drawing::Point(766, 553);
			this->button_clear_Viginer->Name = L"button_clear_Viginer";
			this->button_clear_Viginer->Size = System::Drawing::Size(129, 34);
			this->button_clear_Viginer->TabIndex = 36;
			this->button_clear_Viginer->Text = L"Очистить поля";
			this->button_clear_Viginer->UseVisualStyleBackColor = true;
			this->button_clear_Viginer->Click += gcnew System::EventHandler(this, &MainForm::button_clear_Viginer_Click);
			// 
			// label9
			// 
			this->label9->AutoSize = true;
			this->label9->Location = System::Drawing::Point(37, 408);
			this->label9->Name = L"label9";
			this->label9->Size = System::Drawing::Size(157, 16);
			this->label9->TabIndex = 35;
			this->label9->Text = L"Дешифрованный текст";
			// 
			// textBox_TextDencrypt
			// 
			this->textBox_TextDencrypt->Location = System::Drawing::Point(210, 405);
			this->textBox_TextDencrypt->Multiline = true;
			this->textBox_TextDencrypt->Name = L"textBox_TextDencrypt";
			this->textBox_TextDencrypt->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_TextDencrypt->Size = System::Drawing::Size(685, 130);
			this->textBox_TextDencrypt->TabIndex = 34;
			// 
			// label8
			// 
			this->label8->AutoSize = true;
			this->label8->Location = System::Drawing::Point(37, 254);
			this->label8->Name = L"label8";
			this->label8->Size = System::Drawing::Size(157, 16);
			this->label8->TabIndex = 33;
			this->label8->Text = L"Зашифрованный текст";
			// 
			// textBox_TextEncrypt
			// 
			this->textBox_TextEncrypt->Location = System::Drawing::Point(210, 251);
			this->textBox_TextEncrypt->Multiline = true;
			this->textBox_TextEncrypt->Name = L"textBox_TextEncrypt";
			this->textBox_TextEncrypt->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_TextEncrypt->Size = System::Drawing::Size(685, 135);
			this->textBox_TextEncrypt->TabIndex = 32;
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Location = System::Drawing::Point(37, 131);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(111, 16);
			this->label7->TabIndex = 31;
			this->label7->Text = L"Исходный текст";
			// 
			// textBox_from_File
			// 
			this->textBox_from_File->Location = System::Drawing::Point(210, 128);
			this->textBox_from_File->Multiline = true;
			this->textBox_from_File->Name = L"textBox_from_File";
			this->textBox_from_File->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_from_File->Size = System::Drawing::Size(685, 117);
			this->textBox_from_File->TabIndex = 30;
			// 
			// label_filename
			// 
			this->label_filename->AutoSize = true;
			this->label_filename->Location = System::Drawing::Point(207, 53);
			this->label_filename->Name = L"label_filename";
			this->label_filename->Size = System::Drawing::Size(120, 16);
			this->label_filename->TabIndex = 29;
			this->label_filename->Text = L"Название файла";
			// 
			// button_Open_File
			// 
			this->button_Open_File->Location = System::Drawing::Point(40, 46);
			this->button_Open_File->Name = L"button_Open_File";
			this->button_Open_File->Size = System::Drawing::Size(151, 34);
			this->button_Open_File->TabIndex = 28;
			this->button_Open_File->Text = L"Открыть файл";
			this->button_Open_File->UseVisualStyleBackColor = true;
			this->button_Open_File->Click += gcnew System::EventHandler(this, &MainForm::button_Open_File_Click);
			// 
			// textBox_key_Viginer
			// 
			this->textBox_key_Viginer->Location = System::Drawing::Point(210, 90);
			this->textBox_key_Viginer->Name = L"textBox_key_Viginer";
			this->textBox_key_Viginer->Size = System::Drawing::Size(685, 22);
			this->textBox_key_Viginer->TabIndex = 27;
			// 
			// label15
			// 
			this->label15->AutoSize = true;
			this->label15->Location = System::Drawing::Point(37, 93);
			this->label15->Name = L"label15";
			this->label15->Size = System::Drawing::Size(154, 16);
			this->label15->TabIndex = 26;
			this->label15->Text = L"Ключ для шифрования";
			// 
			// button_Viginer
			// 
			this->button_Viginer->Location = System::Drawing::Point(210, 553);
			this->button_Viginer->Name = L"button_Viginer";
			this->button_Viginer->Size = System::Drawing::Size(236, 34);
			this->button_Viginer->TabIndex = 25;
			this->button_Viginer->Text = L"Зашифровать / Расшифровать";
			this->button_Viginer->UseVisualStyleBackColor = true;
			this->button_Viginer->Click += gcnew System::EventHandler(this, &MainForm::button_Viginer_Click);
			// 
			// tabPage_Pleifer
			// 
			this->tabPage_Pleifer->Controls->Add(this->label14);
			this->tabPage_Pleifer->Controls->Add(this->label_name_file_Pleif);
			this->tabPage_Pleifer->Controls->Add(this->button_open_file_Pleifer);
			this->tabPage_Pleifer->Controls->Add(this->button_Pleifer_enc_dec);
			this->tabPage_Pleifer->Controls->Add(this->button_clear_Pleif);
			this->tabPage_Pleifer->Controls->Add(this->textBox_Pleif_Decoded);
			this->tabPage_Pleifer->Controls->Add(this->label13);
			this->tabPage_Pleifer->Controls->Add(this->textBox_Pleif_Encoded);
			this->tabPage_Pleifer->Controls->Add(this->label12);
			this->tabPage_Pleifer->Controls->Add(this->textBox_Pleif_Mess);
			this->tabPage_Pleifer->Controls->Add(this->label11);
			this->tabPage_Pleifer->Controls->Add(this->textBox_Pleif_key);
			this->tabPage_Pleifer->Controls->Add(this->label10);
			this->tabPage_Pleifer->Location = System::Drawing::Point(4, 25);
			this->tabPage_Pleifer->Name = L"tabPage_Pleifer";
			this->tabPage_Pleifer->Size = System::Drawing::Size(952, 607);
			this->tabPage_Pleifer->TabIndex = 2;
			this->tabPage_Pleifer->Text = L"Шифр Плейфера";
			this->tabPage_Pleifer->UseVisualStyleBackColor = true;
			// 
			// label_name_file_Pleif
			// 
			this->label_name_file_Pleif->AutoSize = true;
			this->label_name_file_Pleif->Location = System::Drawing::Point(212, 63);
			this->label_name_file_Pleif->Name = L"label_name_file_Pleif";
			this->label_name_file_Pleif->Size = System::Drawing::Size(120, 16);
			this->label_name_file_Pleif->TabIndex = 31;
			this->label_name_file_Pleif->Text = L"Название файла";
			// 
			// button_open_file_Pleifer
			// 
			this->button_open_file_Pleifer->Location = System::Drawing::Point(45, 56);
			this->button_open_file_Pleifer->Name = L"button_open_file_Pleifer";
			this->button_open_file_Pleifer->Size = System::Drawing::Size(151, 34);
			this->button_open_file_Pleifer->TabIndex = 30;
			this->button_open_file_Pleifer->Text = L"Открыть файл";
			this->button_open_file_Pleifer->UseVisualStyleBackColor = true;
			this->button_open_file_Pleifer->Click += gcnew System::EventHandler(this, &MainForm::button_open_file_Pleifer_Click);
			// 
			// button_Pleifer_enc_dec
			// 
			this->button_Pleifer_enc_dec->Location = System::Drawing::Point(255, 559);
			this->button_Pleifer_enc_dec->Name = L"button_Pleifer_enc_dec";
			this->button_Pleifer_enc_dec->Size = System::Drawing::Size(280, 35);
			this->button_Pleifer_enc_dec->TabIndex = 25;
			this->button_Pleifer_enc_dec->Text = L"Зашифровать / Расшифровать";
			this->button_Pleifer_enc_dec->UseVisualStyleBackColor = true;
			this->button_Pleifer_enc_dec->Click += gcnew System::EventHandler(this, &MainForm::button_Pleifer_enc_dec_Click);
			// 
			// button_clear_Pleif
			// 
			this->button_clear_Pleif->Location = System::Drawing::Point(806, 559);
			this->button_clear_Pleif->Name = L"button_clear_Pleif";
			this->button_clear_Pleif->Size = System::Drawing::Size(120, 35);
			this->button_clear_Pleif->TabIndex = 23;
			this->button_clear_Pleif->Text = L"Очистить поля";
			this->button_clear_Pleif->UseVisualStyleBackColor = true;
			this->button_clear_Pleif->Click += gcnew System::EventHandler(this, &MainForm::button_clear_Pleif_Click);
			// 
			// textBox_Pleif_Decoded
			// 
			this->textBox_Pleif_Decoded->Location = System::Drawing::Point(255, 423);
			this->textBox_Pleif_Decoded->Multiline = true;
			this->textBox_Pleif_Decoded->Name = L"textBox_Pleif_Decoded";
			this->textBox_Pleif_Decoded->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_Pleif_Decoded->Size = System::Drawing::Size(671, 111);
			this->textBox_Pleif_Decoded->TabIndex = 22;
			// 
			// label13
			// 
			this->label13->AutoSize = true;
			this->label13->Location = System::Drawing::Point(42, 426);
			this->label13->Name = L"label13";
			this->label13->Size = System::Drawing::Size(157, 16);
			this->label13->TabIndex = 21;
			this->label13->Text = L"Дешифрованный текст";
			// 
			// textBox_Pleif_Encoded
			// 
			this->textBox_Pleif_Encoded->Location = System::Drawing::Point(255, 306);
			this->textBox_Pleif_Encoded->Multiline = true;
			this->textBox_Pleif_Encoded->Name = L"textBox_Pleif_Encoded";
			this->textBox_Pleif_Encoded->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_Pleif_Encoded->Size = System::Drawing::Size(671, 111);
			this->textBox_Pleif_Encoded->TabIndex = 20;
			// 
			// label12
			// 
			this->label12->AutoSize = true;
			this->label12->Location = System::Drawing::Point(42, 309);
			this->label12->Name = L"label12";
			this->label12->Size = System::Drawing::Size(157, 16);
			this->label12->TabIndex = 19;
			this->label12->Text = L"Зашифрованный текст";
			// 
			// textBox_Pleif_Mess
			// 
			this->textBox_Pleif_Mess->Location = System::Drawing::Point(255, 189);
			this->textBox_Pleif_Mess->Multiline = true;
			this->textBox_Pleif_Mess->Name = L"textBox_Pleif_Mess";
			this->textBox_Pleif_Mess->ScrollBars = System::Windows::Forms::ScrollBars::Vertical;
			this->textBox_Pleif_Mess->Size = System::Drawing::Size(671, 111);
			this->textBox_Pleif_Mess->TabIndex = 18;
			// 
			// label11
			// 
			this->label11->AutoSize = true;
			this->label11->Location = System::Drawing::Point(42, 192);
			this->label11->Name = L"label11";
			this->label11->Size = System::Drawing::Size(111, 16);
			this->label11->TabIndex = 17;
			this->label11->Text = L"Исходный текст";
			// 
			// textBox_Pleif_key
			// 
			this->textBox_Pleif_key->Location = System::Drawing::Point(255, 140);
			this->textBox_Pleif_key->Multiline = true;
			this->textBox_Pleif_key->Name = L"textBox_Pleif_key";
			this->textBox_Pleif_key->Size = System::Drawing::Size(671, 29);
			this->textBox_Pleif_key->TabIndex = 16;
			// 
			// label10
			// 
			this->label10->AutoSize = true;
			this->label10->Location = System::Drawing::Point(42, 143);
			this->label10->Name = L"label10";
			this->label10->Size = System::Drawing::Size(128, 16);
			this->label10->TabIndex = 15;
			this->label10->Text = L"Ключ шифрования";
			// 
			// button_Close
			// 
			this->button_Close->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->button_Close->Location = System::Drawing::Point(860, 654);
			this->button_Close->Name = L"button_Close";
			this->button_Close->Size = System::Drawing::Size(108, 27);
			this->button_Close->TabIndex = 1;
			this->button_Close->Text = L"Выход";
			this->button_Close->UseVisualStyleBackColor = true;
			this->button_Close->Click += gcnew System::EventHandler(this, &MainForm::button_Close_Click);
			// 
			// openFileDialog_ToCipher
			// 
			this->openFileDialog_ToCipher->FileName = L"openFileDialog";
			// 
			// label14
			// 
			this->label14->AutoSize = true;
			this->label14->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14.25F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->label14->ForeColor = System::Drawing::Color::Blue;
			this->label14->Location = System::Drawing::Point(738, 14);
			this->label14->Name = L"label14";
			this->label14->Size = System::Drawing::Size(188, 24);
			this->label14->TabIndex = 32;
			this->label14->Text = L"ШИФР ПЛЕЙФЕРА";
			// 
			// label16
			// 
			this->label16->AutoSize = true;
			this->label16->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 14.25F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->label16->ForeColor = System::Drawing::Color::Maroon;
			this->label16->Location = System::Drawing::Point(707, 25);
			this->label16->Name = L"label16";
			this->label16->Size = System::Drawing::Size(188, 24);
			this->label16->TabIndex = 37;
			this->label16->Text = L"ШИФР ВИЖИНЕРА";
			// 
			// MainForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(984, 689);
			this->Controls->Add(this->button_Close);
			this->Controls->Add(this->tabControl1);
			this->Name = L"MainForm";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"Форма шифрования / дешифрования";
			this->tabControl1->ResumeLayout(false);
			this->tabPage_RSA->ResumeLayout(false);
			this->tabPage_RSA->PerformLayout();
			this->groupBox3->ResumeLayout(false);
			this->groupBox3->PerformLayout();
			this->groupBox2->ResumeLayout(false);
			this->groupBox2->PerformLayout();
			this->groupBox_Exp->ResumeLayout(false);
			this->groupBox_Exp->PerformLayout();
			this->groupBox1->ResumeLayout(false);
			this->groupBox1->PerformLayout();
			this->groupBox_pq->ResumeLayout(false);
			this->groupBox_pq->PerformLayout();
			this->tabPage_Vijiner->ResumeLayout(false);
			this->tabPage_Vijiner->PerformLayout();
			this->tabPage_Pleifer->ResumeLayout(false);
			this->tabPage_Pleifer->PerformLayout();
			this->ResumeLayout(false);

		}
#pragma endregion

		/// <summary> Закрываю форму </summary>
		private: System::Void button_Close_Click(System::Object^ sender, System::EventArgs^ e)
		{
			Close();
		}

					 // Возвращает кол-во простых чисел в массиве
		private: System::Int32 CountPrimeNumberInArray(long arrPrimeNumber[], int length)
		{
			int count = 0;
			for (long i = 0; i < length; i++)
			{
				if (arrPrimeNumber[i] > 0)
					count++;
			}
			return count;
		}

					 // Простые числа через решето Эратосфена
					 // length - кол-во простых чисел
		private: System::Void PrimeNumbersSieveOfEratosthenes(int length)
		{
			// числа до COUNT_MAX_ARRAY для поиска в них простых чисел
			for (int i = 0; i < length; i++)
			{
				PrimeNumbersArray[i] = i;
			}
			// поиск простых чисел
			for (int i = 0; i < length; i++)
			{
				if (i != 0 && i != 1)
				{
					for (int j = i + 1; j < length; j++)
					{
						if (PrimeNumbersArray[j] != 0 && j % i == 0)
							PrimeNumbersArray[j] = 0; // обнуляю, если делится 
					}
				}
			}
			// вычисляю кол-во простых чисел
			countPrimeN = CountPrimeNumberInArray(PrimeNumbersArray, length);
			// формирую массив простых чисел
			arrPrimeNumber = new int[countPrimeN]; // динамическое выделение памяти для массива
			int p = 0;
			for (int i = 0; i < length; i++)
			{
				if (PrimeNumbersArray[i] > 0)
				{
					arrPrimeNumber[p] = PrimeNumbersArray[i];
					p++;
				}
			}
		}

					 // Двоичное преобразование
		private: System::Int32 BianaryTransform(int num, int bin_num[])
		{
			int i = 0, mod = 0;

			// Преобразуется в двоичный, обратный временно сохраняется в массиве temp []
			while (num != 0)
			{
				mod = num % 2;
				bin_num[i] = mod;
				num = num / 2;
				i++;
			}

			// Возвращает количество цифр в двоичных числах
			return i;
		}

					 // Повторное возведение в квадрат в степень
		private: System::Int64 Modular_Exonentiation(long long a, int b, int n)
		{
			int c = 0, bin_num[1000];
			long long d = 1;
			int k = BianaryTransform(b, bin_num) - 1;

			for (int i = k; i >= 0; i--)
			{
				c = 2 * c;
				d = (d * d) % n;
				if (bin_num[i] == 1)
				{
					c = c + 1;
					d = (d * a) % n;
				}
			}
			return d;
		}

					 // Генерация простых чисел в пределах 1000
		private: System::Int32 ProducePrimeNumber(int prime[])
		{
			int c = 0, vis[1001];
			memset(vis, 0, sizeof(vis));
			for (int i = 2; i <= 1000; i++)
			{
				if (!vis[i])
				{
					prime[c++] = i;
					for (int j = i * i; j <= 1000; j += i)
						vis[j] = 1;
				}
			}
			return c;
		}

					 // Расширенный алгоритм Евклида
		private: System::Int32 Exgcd(int m, int n, int& x)
		{
			int x1, y1, x0, y0, y;
			x0 = 1; y0 = 0;
			x1 = 0; y1 = 1;
			x = 0; y = 1;
			int r = m % n;
			int q = (m - r) / n;
			while (r)
			{
				x = x0 - q * x1; y = y0 - q * y1;
				x0 = x1; y0 = y1;
				x1 = x; y1 = y;
				m = n; n = r; r = m % n;
				q = (m - r) / n;
			}
			return n;
		}

					 // Инициализация RSA
		private: System::Void RSA_Initialize()
		{
			// простые числа через решето Эратосфена
			PrimeNumbersSieveOfEratosthenes(COUNT_MAX_ARRAY);

			// Случайно возьмем два простых числа p, q
			srand((unsigned)time(NULL));
			int ranNum1 = rand() % countPrimeN;
			int ranNum2 = rand() % countPrimeN;

			int p = arrPrimeNumber[ranNum1];
			int	q = arrPrimeNumber[ranNum2];

			n = p * q;

			int On = (p - 1) * (q - 1); // функция Эйлера

			// Используем расширенный алгоритм Евклида, чтобы найти e, d
			for (int j = 3; j < On; j += 1331)
			{
				int gcd = Exgcd(j, On, d);
				if (gcd == 1 && d > 0)
				{
					open_exponent = j;
					break;
				}
			}

			// вывожу на форму основные показатели
			VarsOnForm(p, q, n, On, open_exponent, d);
		}

					 // Записываю в поля на форму
		private: System::Void VarsOnForm(int p, int q, int n, int On, int open_exponent, int d)
		{
			textBox_pPrime->Text = p.ToString();
			textBox_qPrime->Text = q.ToString();
			textBox_n->Text = n.ToString();
			textBox_Ailer->Text = On.ToString();
			textBox_dPrivate->Text = d.ToString();
			textBox_ePublic->Text = open_exponent.ToString();
			label_public_key->Text = "Открытый ключ {e,n} = {" + open_exponent.ToString() + "," + n.ToString() + "}";
			label_private_key->Text = "Закрытый ключ {d,n} = {" + d.ToString() + "," + n.ToString() + "}";
		}

					 // шифрование RSA
		private: System::Void RSA_Encrypt()
		{
			int i = 0;
			for (i = 0; i < 100; i++)
			{
				Ciphertext[i] = Modular_Exonentiation(Plaintext[i], open_exponent, n);
				textBox_NumbersEncrypt->Text += Ciphertext[i].ToString() + " ";
			}
		}

					 // Расшифровка RSA
		private: System::Void RSA_Decrypt()
		{
			int i = 0;
			for (i = 0; i < 100; i++)
			{
				Ciphertext[i] = Modular_Exonentiation(Ciphertext[i], d, n);
				textBox_NumbersDecrypt->Text += Ciphertext[i].ToString() + " ";
			}
		}

					 // Инициализация данных для шифрования - массив чисел
		private: System::Void InitializeNumbers()
		{
			int i;
			srand((unsigned)time(NULL));
			for (i = 0; i < 100; i++)
			{
				Plaintext[i] = rand() % 1000;
				textBox_Numbers->Text += Plaintext[i].ToString() + " ";
			}
		}

					 // очистка полей
		private: System::Void button_Clear_Click(System::Object^ sender, System::EventArgs^ e)
		{
			textBox_Ailer->Clear();
			textBox_dPrivate->Clear();
			textBox_ePublic->Clear();
			textBox_n->Clear();
			textBox_pPrime->Clear();
			textBox_qPrime->Clear();
			textBox_Numbers->Clear();
			textBox_NumbersDecrypt->Clear();
			textBox_NumbersEncrypt->Clear();
			label_public_key->Text = "Открытый ключ {e,n} ";
			label_private_key->Text = "Закрытый ключ {d,n} ";
		}
		private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e)
		{
			RSA_Initialize();
		}

		private: System::Void button_enc_decr_Click(System::Object^ sender, System::EventArgs^ e)
		{
			textBox_Numbers->Clear();
			textBox_NumbersDecrypt->Clear();
			textBox_NumbersEncrypt->Clear();
			// определяю какой объект для шифрования выбран
			if (radioButton_array->Checked == true) // массив чисел
			{
				InitializeNumbers();
				// Инициализация RSA, если не рассчитаны ключи
				if (textBox_ePublic->Text->Trim() == "" && textBox_dPrivate->Text->Trim() == "")
					RSA_Initialize();
				RSA_Encrypt();
				RSA_Decrypt();
			}
			else // файл
			{
				OpenFileRSA(0);
			}
		}

		private: System::Void radioButton_file_CheckedChanged(System::Object^ sender, System::EventArgs^ e)
		{
			button_enc_decr->Text = "Шифровать / Дешифровать текстовый файл";
			label_PlainText->Text = "Исходный текст";
			label_CipherText->Text = "Зашифрованный текст";
			label_DecryptedText->Text = "Дешифрованный текст";
			button_ReadDecryptText->Visible = true;
			label_FileNameRSA->Visible = true;
		}

		private: System::Void radioButton_array_CheckedChanged(System::Object^ sender, System::EventArgs^ e)
		{
			button_enc_decr->Text = "Шифровать / Дешифровать массив случайных чисел";
			label_PlainText->Text = "Исходные числа";
			label_CipherText->Text = "Зашифрованные числа";
			label_DecryptedText->Text = "Дешифрованные числа";
			button_ReadDecryptText->Visible = false;
			label_FileNameRSA->Visible = false;
		}

					 // открытие файла для RSA
					 // decr - признак в какое поле писать прочитанное из файла: 0 - в поле исходного текста; 1 - в поле дешифрованного текста
		private: System::Void OpenFileRSA(int decr)
		{
			// определяю, какие файлы выбирать
			openFileDialog_ToCipher->Filter = "Текстовые файлы(*.TXT)|*.TXT";
			if (openFileDialog_ToCipher->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				//Получаю путь к файлу в типе System::String^ :
				String^ path_file_RSA = openFileDialog_ToCipher->FileName;
				label_FileNameRSA->Text = path_file_RSA;

				// Чтение текстового файла:
				try
				{ // Создание экземпляра StreamReader для чтения из файла
					auto readFile = gcnew	IO::StreamReader(path_file_RSA, System::Text::Encoding::GetEncoding("utf-8"));
					if (decr == 0)
					{
						textBox_Numbers->Text = readFile->ReadToEnd();
					}
					else
					{
						textBox_NumbersDecrypt->Text = readFile->ReadToEnd();
					}
					readFile->Close();

					// шифрование / дешифрование файла
					if (decr == 0)
						Encrypt_Decrypt_File();
				}
				catch (IO::FileNotFoundException^ E)
				{
					MessageBox::Show(E->Message + "\nНет такого файла", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
				catch (Exception^ E)
				{
					MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
			}
		}

		private: System::Void button_ReadDecryptText_Click(System::Object^ sender, System::EventArgs^ e)
		{
			OpenFileRSA(1);
		}

		private: System::Void Encrypt_Decrypt_File()
		{
			const int bitLength = 10;
			String^ path_file_RSA = label_FileNameRSA->Text;
			int pos;

			if (File::Exists(path_file_RSA)) // если файл существует
			{
				auto readFile = gcnew IO::BinaryReader(IO::File::Open(path_file_RSA, IO::FileMode::Open));
				try
				{
					readFile->BaseStream->Position = 0;
					long long lengthFile = readFile->BaseStream->Length;
					long long currentLength = 0; // счетчик считанных байт

					std::vector<long long> Plaintext_fromFile(lengthFile);
					std::vector<long long> Ciphertext_fromFile(lengthFile);

					// Читаю данные
					array<Byte>^ arrayFile = readFile->ReadBytes(bitLength);
					currentLength = arrayFile->Length; // получаю первое кол-во прочитанных байт
					pos = 0; // позиция для записи в массив
					while (currentLength <= lengthFile)
					{
						// записываю данные для шифрования
						for (int i = 0; i < arrayFile->Length; i++)
						{
							Plaintext_fromFile[pos] = arrayFile[i];
							pos++;
						}
						readFile->BaseStream->Position = currentLength; // устанавливаю позицию указателя
						arrayFile = readFile->ReadBytes(bitLength); // следующие байты данных
						currentLength += arrayFile->Length; // увеличиваю счетчик
						if (arrayFile->Length == 0) // если конец файла и читать нечего, то выход из цикла
							break;
					}

					// вывод массива в поле
					/*for (long long i = 0; i < lengthFile; i++)
						textBox_Numbers->Text += Plaintext_fromFile[i].ToString() + " ";*/

						// Инициализация RSA, если не рассчитаны ключи
					if (textBox_ePublic->Text == "" && textBox_dPrivate->Text == "")
						RSA_Initialize();

					// шифрование RSA
					long long i = 0;
					for (i = 0; i < lengthFile; i++)
					{
						Ciphertext_fromFile[i] = Modular_Exonentiation(Plaintext_fromFile[i], open_exponent, n);
						textBox_NumbersEncrypt->Text += Ciphertext_fromFile[i].ToString() + " ";
					}
					// Создание экземпляра StreamWriter для записи в файл шифрованных данных
					try
					{
						auto encoding = System::Text::Encoding::GetEncoding("utf-8");
						auto writeFile = gcnew	IO::StreamWriter("CipherText.txt", false, encoding);
						for (i = 0; i < lengthFile; i++)
						{
							writeFile->WriteLine(Ciphertext_fromFile[i]);
						}
						writeFile->Close();
					}
					catch (System::Exception^ E) // если ошибка
					{
						MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
					}

					// Расшифровка RSA
					for (i = 0; i < lengthFile; i++)
					{
						Ciphertext_fromFile[i] = Modular_Exonentiation(Ciphertext_fromFile[i], d, n);
						//textBox_NumbersDecrypt->Text += Ciphertext_fromFile[i].ToString() + " ";
					}

					// Создаю поток writeFile для записи расшифрованных байт в файл
					try
					{
						auto encoding = System::Text::Encoding::GetEncoding("utf-8");
						//auto encoding = System::Text::Encoding::GetEncoding(1251);
						// Создание экземпляра StreamWriter для записи в файл:
						auto writeFile = gcnew	IO::StreamWriter("DecryptedText.txt", false, encoding);
						for (i = 0; i < lengthFile; i++)
						{
							writeFile->Write(Ciphertext_fromFile[i]);
						}
						writeFile->Close();
					}
					catch (System::Exception^ E) // если ошибка
					{
						MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
					}
				}
				finally
				{
					if (readFile)
						delete (IDisposable^)readFile; // закрываю файл и удаляю объект дескриптора файла
				}
			}
			else
				MessageBox::Show("Файла '" + path_file_RSA + "' не существует", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
		}

					 /////////////////////////// Шифр Вижинера //////////////////////////////////////////////

		private: void encrypt_viginer(char* filename, char* key, int n)
		{
			int i, count = 0, size = 0;
			char ch;

			FILE* in, * out;
			in = fopen(filename, "r");
			if (in == NULL)
			{
				printf("Cannot open source file.\n");
				exit(1);
			}

			out = fopen("CipherText.txt", "w+");
			if (out == NULL)
			{
				printf("Cannot open destination file.\n");
				exit(1);
			}

			fseek(in, 0, SEEK_END);     // ищем конец файла
			size = ftell(in);           // получаем указатель на текущий файл
			fseek(in, 0, SEEK_SET);     // вернуться к началу файла

			for (i = n; i < size - 1; i++)
			{
				key[i] = key[i - n];
			}

			while (count != size)
			{
				ch = getc(in);
				if (isupper(ch))
				{
					putc(table[key[count] - 65][ch - 65] + 65, out);
				}
				else
				{
					putc(table[key[count] - 65][ch - 97 + 26] + 97, out);
				}
				count++;
			}

			fclose(in);
			fclose(out);
		}

		private: void decrypt_viginer(char* key)
		{
			int i, j, size = 0, count = 0;
			char ch;

			FILE* in, * out;
			in = fopen("CipherText.txt", "r");

			if (in == NULL)
			{
				printf("Cannot open encrypted file.\n");
				exit(1);
			}

			out = fopen("DecryptedText.txt", "w+");
			if (out == NULL)
			{
				printf("Cannot open destination file.\n");
				exit(1);
			}

			fseek(in, 0, SEEK_END); // ищем конец файла
			size = ftell(in);    // получаем указатель на текущий файл
			fseek(in, 0, SEEK_SET); // вернуться к началу файла

			while (count != size)
			{
				ch = getc(in);
				if (isupper(ch))
				{
					for (i = 0; i < 26; i++)
					{
						if (table[key[count] - 65][i] == ch - 65)
						{
							fputc(i + 65, out);
						}
					}
				}
				else
				{
					for (i = 26; i < 52; i++)
					{
						if (table[key[count] - 65][i] == ch - 97)
						{
							fputc(i + 97 - 26, out);
						}
					}
				}
				count++;
			}
			fclose(out);
			fclose(in);
		}

		private: void init_matrix()
		{
			int i, j;

			for (i = 0; i < 26; i++)
			{
				for (j = 0; j < 26 - i; j++)
				{
					table[i][j] = j + i;
				}

				for (j = 26 - i; j < 26; j++)
				{
					table[i][j] = (j + i) - 26;
				}

				for (j = 26; j < 52 - i; j++)
				{
					table[i][j] = j + i - 26;
				}

				for (j = 52 - i; j < 52; j++)
				{
					table[i][j] = (j + i) - 52;
				}
			}
		}

		private: void encrypt_decrypt()
		{
			int n = std::strlen(key_viginer);

			int j;
			// преобразовать ключ в верхний регистр
			/*for (j = 0; j < n; j++)
			{
				key_viginer[j] = std::toupper(key_viginer[j]);
			}*/

			init_matrix();

			// зашифровать с помощью шифра Виженера
			encrypt_viginer(filename_viginer, key_viginer, n);

			// расшифровать с помощью шифра Виженера
			decrypt_viginer(key_viginer);
		}

					 ////////////////////////////////////////////////////////////////////////////////////////
		private: System::Void button_Viginer_Click(System::Object^ sender, System::EventArgs^ e)
		{
			//msclr::interop::marshal_context context;
			//textBox_key_Viginer->Text = context.marshal_as<System::String^>(key_viginer);

			if (label_filename->Text->Trim() == "")
			{
				MessageBox::Show("Не выбран файл для шифрования.", "Предупреждение", MessageBoxButtons::OK, MessageBoxIcon::Warning);
				return;
			}

			if (textBox_key_Viginer->Text->Trim() == "")
			{
				MessageBox::Show("Поле ключа пустое. Необходимо ввести ключ.", "Предупреждение", MessageBoxButtons::OK, MessageBoxIcon::Warning);
				return;
			}
			// из поля ключа в массив символов
			std::string str = msclr::interop::marshal_as<std::string>(textBox_key_Viginer->Text->ToUpper());
			std::vector<char> chars(str.begin(), str.end());
			chars.push_back('\0');
			for (size_t i = 0; i < chars.size(); i++)
			{
				key_viginer[i] = chars[i];
			}

			if (textBox_from_File->Text->Trim() == "" && label_filename->Text->Trim() != "")
			{
				StreamReader^ file = File::OpenText(label_filename->Text);
				textBox_from_File->Text = file->ReadToEnd();
				file->Close();
			}

			String^ fileTXT = label_filename->Text->Trim();
			String^ keyViginer = textBox_key_Viginer->Text->Trim()->ToUpper();
			int keyLength = keyViginer->Length;

			// инициализация, шифрование, дешифрование
			encrypt_decrypt();

			// Чтение текстового файла:
			try
			{ // Создание экземпляра StreamReader для чтения из файла
				auto readFile = gcnew	IO::StreamReader("CipherText.txt", System::Text::Encoding::GetEncoding("utf-8"));
				textBox_TextEncrypt->Text = readFile->ReadToEnd();
				readFile->Close();

				readFile = gcnew	IO::StreamReader("DecryptedText.txt", System::Text::Encoding::GetEncoding("utf-8"));
				textBox_TextDencrypt->Text = readFile->ReadToEnd();
				readFile->Close();
			}
			catch (IO::FileNotFoundException^ E)
			{
				MessageBox::Show(E->Message + "\nНет такого файла", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
			}
			catch (Exception^ E)
			{
				MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
			}
		}

		private: System::Void button_Open_File_Click(System::Object^ sender, System::EventArgs^ e)
		{
			//msclr::interop::marshal_context context;
			// определяю, какие файлы выбирать
			//openFileDialog_ToCipher->Filter = "Текстовые файлы(*.TXT)|*.TXT|Все файлы (*.*)|*.*";
			openFileDialog_ToCipher->Filter = "Текстовые файлы(*.TXT)|*.TXT";
			if (openFileDialog_ToCipher->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				//Получаю путь к файлу в типе System::String^ :
				String^ path_f = openFileDialog_ToCipher->FileName;
				label_filename->Text = path_f;
				try
				{
					StreamReader^ file = File::OpenText(path_f);
					textBox_from_File->Text = file->ReadToEnd();
					file->Close();
				}
				catch (IO::FileNotFoundException^ E)
				{
					MessageBox::Show(E->Message + "\nНет такого файла", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
				catch (Exception^ E)
				{
					MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
			}
		}

		private: System::Void button_clear_Viginer_Click(System::Object^ sender, System::EventArgs^ e)
		{
			textBox_from_File->Text = "";
			textBox_TextEncrypt->Text = "";
			textBox_TextDencrypt->Text = "";
		}

	 //////////////////////////// Плейфер  /////////////////////////////////////////////////

		private: int Mod(int a, int b)
		{
			return (a % b + b) % b;
		}

		private: char** Create2DArray(int rowCount, int colCount)
		{
			char** arr = new char* [rowCount];

			for (int i = 0; i < rowCount; ++i)
				arr[i] = new char[colCount];

			return arr;
		}

		private: std::string ToUpper(std::string str)
		{
			std::string output = str;
			int strLen = str.size();

			for (int i = 0; i < strLen; ++i)
				output[i] = toupper(output[i]);

			return output;
		}

		private: std::string RemoveChar(std::string str, char ch)
		{
			std::string output = str;

			for (int i = 0; i < output.size(); ++i)
				if (output[i] == ch)
					output = output.erase(i, 1);

			return output;
		}

		private: std::vector<int> FindAllOccurrences(std::string str, char value)
		{
			std::vector<int> indexes;

			int index = 0;
			while ((index = str.find(value, index)) != -1)
				indexes.push_back(index++);

			return indexes;
		}

		private: std::string RemoveAllDuplicates(std::string str, std::vector<int> indexes)
		{
			std::string retVal = str;

			for (int i = indexes.size() - 1; i >= 1; i--)
				retVal = retVal.erase(indexes[i], 1);

			return retVal;
		}

		private: char** GenerateKeySquare(std::string key)
		{
			char** keySquare = Create2DArray(5, 5);
			std::string defaultKeySquare = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
			std::string tempKey = key.empty() ? "CIPHER" : ToUpper(key);

			tempKey = RemoveChar(tempKey, 'J');
			tempKey += defaultKeySquare;

			for (int i = 0; i < 25; ++i)
			{
				std::vector<int> indexes = FindAllOccurrences(tempKey, defaultKeySquare[i]);
				tempKey = RemoveAllDuplicates(tempKey, indexes);
			}

			tempKey = tempKey.substr(0, 25);

			for (int i = 0; i < 25; ++i)
				keySquare[(i / 5)][(i % 5)] = tempKey[i];

			return keySquare;
		}

		private: void GetPosition(char** keySquare, char ch, int* row, int* col)
		{
			if (ch == 'J')
				GetPosition(keySquare, 'I', row, col);

			for (int i = 0; i < 5; ++i)
			{
				for (int j = 0; j < 5; ++j)
				{
					if (keySquare[i][j] == ch)
					{
						*row = i;
						*col = j;
						return;
					}
				}
			}
		}

		private: char* SameRow(char** keySquare, int row, int col1, int col2, int encipher)
		{
			return new char[2]{ keySquare[row][Mod((col1 + encipher), 5)], keySquare[row][Mod((col2 + encipher), 5)] };
		}

		private: char* SameColumn(char** keySquare, int col, int row1, int row2, int encipher)
		{
			return new char[2]{ keySquare[Mod((row1 + encipher), 5)][col], keySquare[Mod((row2 + encipher), 5)][col] };
		}

		private: char* SameRowColumn(char** keySquare, int row, int col, int encipher)
		{
			return new char[2]{ keySquare[Mod((row + encipher), 5)][Mod((col + encipher), 5)], keySquare[Mod((row + encipher), 5)][Mod((col + encipher), 5)] };
		}

		private: char* DifferentRowColumn(char** keySquare, int row1, int col1, int row2, int col2)
		{
			return new char[2]{ keySquare[row1][col2], keySquare[row2][col1] };
		}

		private: std::string RemoveOtherChars(std::string input)
		{
			std::string output = input;
			int strLen = input.size();

			for (int i = 0; i < strLen; ++i)
				if (!isalpha(output[i]))
					output = output.erase(i, 1);

			return output;
		}

		private: std::string AdjustOutput(std::string input, std::string output)
		{
			std::string retVal = output;
			int strLen = input.size();

			for (int i = 0; i < strLen; ++i)
			{
				if (!isalpha(input[i]))
					retVal = retVal.insert(i, 1, input[i]);

				if (islower(input[i]))
					retVal[i] = tolower(retVal[i]);
			}

			return retVal;
		}

		private: std::string Cipher(std::string input, std::string key, bool encipher)
		{
			std::string retVal = "";
			char** keySquare = GenerateKeySquare(key);
			std::string tempInput = RemoveOtherChars(input);
			int e = encipher ? 1 : -1;
			int tempInputLen = tempInput.size();

			if ((tempInputLen % 2) != 0)
				tempInput += "X";

			for (int i = 0; i < tempInputLen; i += 2)
			{
				int row1 = 0;
				int col1 = 0;
				int row2 = 0;
				int col2 = 0;

				GetPosition(keySquare, toupper(tempInput[i]), &row1, &col1);
				GetPosition(keySquare, toupper(tempInput[i + 1]), &row2, &col2);

				if (row1 == row2 && col1 == col2)
				{
					retVal += std::string(SameRowColumn(keySquare, row1, col1, e), 2);
				}
				else if (row1 == row2)
				{
					retVal += std::string(SameRow(keySquare, row1, col1, col2, e), 2);
				}
				else if (col1 == col2)
				{
					retVal += std::string(SameColumn(keySquare, col1, row1, row2, e), 2);
				}
				else
				{
					retVal += std::string(DifferentRowColumn(keySquare, row1, col1, row2, col2), 2);
				}
			}

			retVal = AdjustOutput(input, retVal);

			return retVal;
		}

		private: std::string Encipher(std::string input, std::string key)
		{
			return Cipher(input, key, true);
		}

		private: std::string Decipher(std::string input, std::string key)
		{
			return Cipher(input, key, false);
		}

					 // шифрование / дешифрование
		private: System::Void button_Pleifer_enc_dec_Click(System::Object^ sender, System::EventArgs^ e)
		{
			//textBox_Pleif_key->Clear();
			textBox_Pleif_Encoded->Clear();
			textBox_Pleif_Decoded->Clear();

			if (label_name_file_Pleif->Text->Trim() == "")
			{
				MessageBox::Show("Не выбран файл для шифрования.", "Предупреждение", MessageBoxButtons::OK, MessageBoxIcon::Warning);
				return;
			}

			if (textBox_Pleif_key->Text->Trim() == "")
			{
				MessageBox::Show("Поле ключа пустое. Необходимо ввести ключ.", "Предупреждение", MessageBoxButtons::OK, MessageBoxIcon::Warning);
				return;
			}

			if (textBox_Pleif_Mess->Text->Trim() == "" && label_name_file_Pleif->Text->Trim() != "")
			{
				StreamReader^ file = File::OpenText(label_name_file_Pleif->Text);
				textBox_Pleif_Mess->Text = file->ReadToEnd();
				file->Close();
			}

			// ключ для шифрования в строковую переменную
			std::string strKey = msclr::interop::marshal_as<std::string>(textBox_Pleif_key->Text);
			// текст для шифрования в строковую переменную
			std::string strText = msclr::interop::marshal_as<std::string>(textBox_Pleif_Mess->Text);
			// разбиваю на слова, если есть пробелы в слове для шифрования
			std::vector<std::string> tokens; // массив слов
			std::string token; // слово
			std::stringstream ss(strText); // потоковое чтение строки
			while (getline(ss, token, ' ')) // получаю слово до пробела
			{
				tokens.push_back(token);
			}
			// шифрую по словам
			for (size_t k = 0; k < tokens.size(); k++)
			{
				// запись шифрованных данных в поле
				std::string cipherText = Encipher(tokens[k], strKey);
				textBox_Pleif_Encoded->Text += msclr::interop::marshal_as<System::String^>(cipherText) + " ";
				// дешифрование
				std::string plainText = Decipher(cipherText, strKey);
				textBox_Pleif_Decoded->Text += msclr::interop::marshal_as<System::String^>(plainText) + " ";
			}
			//textBox_Pleif_Decoded->Text = textBox_Pleif_Decoded->Text->Substring(0, textBox_Pleif_Decoded->Text->Length-2);
			// записываю в файлы
			WriteToFilePleifer("CipherText.txt", "utf-8", textBox_Pleif_Encoded->Text);
			WriteToFilePleifer("DecryptedText.txt", "utf-8", textBox_Pleif_Decoded->Text);
		}
    
		// данные в файл
		// NameFile - название файла; NameEncoding - кодировка, например, "utf-8"
		// TextBoxValue - данные для записи
		private: System::Void WriteToFilePleifer(System::String^ NameFile, System::String^ NameEncoding, System::String^ TextBoxValue)
		{
			// Создаю поток writeFile для записи расшифрованных байт в файл
			try
			{
				auto encoding = System::Text::Encoding::GetEncoding(NameEncoding);
				//auto encoding = System::Text::Encoding::GetEncoding(1251);
				// Создание экземпляра StreamWriter для записи в файл:
				auto writeFile = gcnew	IO::StreamWriter(NameFile, false, encoding);
				for (int i = 0; i < TextBoxValue->Length; i++)
				{
					writeFile->Write(TextBoxValue[i]);
				}
				writeFile->Close();
			}
			catch (System::Exception^ E) // если ошибка
			{
				MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
			}
		}

		private: System::Void button_clear_Pleif_Click(System::Object^ sender, System::EventArgs^ e)
		{
			textBox_Pleif_key->Clear();
			textBox_Pleif_Mess->Clear();
			textBox_Pleif_Encoded->Clear();
			textBox_Pleif_Decoded->Clear();
		}

					 // открываю файл для плейфнера
		private: System::Void button_open_file_Pleifer_Click(System::Object^ sender, System::EventArgs^ e)
		{
			openFileDialog_ToCipher->Filter = "Текстовые файлы(*.TXT)|*.TXT";
			if (openFileDialog_ToCipher->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				//Получаю путь к файлу в типе System::String^ :
				String^ path_f = openFileDialog_ToCipher->FileName;
				label_name_file_Pleif->Text = path_f;
				try
				{
					StreamReader^ file = File::OpenText(path_f);
					textBox_Pleif_Mess->Text = file->ReadToEnd();
					file->Close();
				}
				catch (IO::FileNotFoundException^ E)
				{
					MessageBox::Show(E->Message + "\nНет такого файла", "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
				catch (Exception^ E)
				{
					MessageBox::Show(E->Message, "Ошибка", MessageBoxButtons::OK, MessageBoxIcon::Error);
				}
			}
		}

};
}
