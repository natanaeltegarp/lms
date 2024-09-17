PGDMP                      |            lms    16.4    16.4 !    
           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false                       0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false                       1262    16397    lms    DATABASE     ~   CREATE DATABASE lms WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE lms;
                postgres    false            �            1259    16428 
   enrollment    TABLE     �   CREATE TABLE public.enrollment (
    id_kelas integer NOT NULL,
    id_user integer NOT NULL,
    token character(20) NOT NULL
);
    DROP TABLE public.enrollment;
       public         heap    postgres    false            �            1259    16413 
   kelas_ajar    TABLE     �   CREATE TABLE public.kelas_ajar (
    nama_mapel character(255) NOT NULL,
    kelas character(5) NOT NULL,
    id_kelas integer NOT NULL
);
    DROP TABLE public.kelas_ajar;
       public         heap    postgres    false            �            1259    16473    kelas_ajar_id_kelas_seq    SEQUENCE     �   CREATE SEQUENCE public.kelas_ajar_id_kelas_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.kelas_ajar_id_kelas_seq;
       public          postgres    false    217                       0    0    kelas_ajar_id_kelas_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.kelas_ajar_id_kelas_seq OWNED BY public.kelas_ajar.id_kelas;
          public          postgres    false    219            �            1259    16486    kuis    TABLE     �   CREATE TABLE public.kuis (
    id_kuis integer NOT NULL,
    id_kelas integer NOT NULL,
    judul_kuis character(255) NOT NULL
);
    DROP TABLE public.kuis;
       public         heap    postgres    false            �            1259    16485    kuis_id_kuis_seq    SEQUENCE     �   CREATE SEQUENCE public.kuis_id_kuis_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.kuis_id_kuis_seq;
       public          postgres    false    221                       0    0    kuis_id_kuis_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.kuis_id_kuis_seq OWNED BY public.kuis.id_kuis;
          public          postgres    false    220            �            1259    16398    users    TABLE     �  CREATE TABLE public.users (
    id integer NOT NULL,
    fullname character varying(100) NOT NULL,
    username character varying(50) NOT NULL,
    password text NOT NULL,
    email character varying(100) NOT NULL,
    role character varying(10) NOT NULL,
    nisn_or_nuptk character varying(50),
    CONSTRAINT users_check CHECK (((((role)::text = 'student'::text) AND (nisn_or_nuptk IS NOT NULL)) OR (((role)::text = 'teacher'::text) AND (nisn_or_nuptk IS NOT NULL)) OR ((role IS NULL) AND (nisn_or_nuptk IS NULL)))),
    CONSTRAINT users_role_check CHECK (((role)::text = ANY (ARRAY[('student'::character varying)::text, ('teacher'::character varying)::text])))
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16405    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    215                       0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    216            _           2604    16474    kelas_ajar id_kelas    DEFAULT     z   ALTER TABLE ONLY public.kelas_ajar ALTER COLUMN id_kelas SET DEFAULT nextval('public.kelas_ajar_id_kelas_seq'::regclass);
 B   ALTER TABLE public.kelas_ajar ALTER COLUMN id_kelas DROP DEFAULT;
       public          postgres    false    219    217            `           2604    16489    kuis id_kuis    DEFAULT     l   ALTER TABLE ONLY public.kuis ALTER COLUMN id_kuis SET DEFAULT nextval('public.kuis_id_kuis_seq'::regclass);
 ;   ALTER TABLE public.kuis ALTER COLUMN id_kuis DROP DEFAULT;
       public          postgres    false    221    220    221            ^           2604    16406    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    215                      0    16428 
   enrollment 
   TABLE DATA           >   COPY public.enrollment (id_kelas, id_user, token) FROM stdin;
    public          postgres    false    218   8%                 0    16413 
   kelas_ajar 
   TABLE DATA           A   COPY public.kelas_ajar (nama_mapel, kelas, id_kelas) FROM stdin;
    public          postgres    false    217   f%                 0    16486    kuis 
   TABLE DATA           =   COPY public.kuis (id_kuis, id_kelas, judul_kuis) FROM stdin;
    public          postgres    false    221   �%                 0    16398    users 
   TABLE DATA           ]   COPY public.users (id, fullname, username, password, email, role, nisn_or_nuptk) FROM stdin;
    public          postgres    false    215   '&                  0    0    kelas_ajar_id_kelas_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.kelas_ajar_id_kelas_seq', 7, true);
          public          postgres    false    219                       0    0    kuis_id_kuis_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.kuis_id_kuis_seq', 5, true);
          public          postgres    false    220                       0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 15, true);
          public          postgres    false    216            l           2606    16432    enrollment enrollment_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT enrollment_pkey PRIMARY KEY (id_kelas, id_user);
 D   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT enrollment_pkey;
       public            postgres    false    218    218            j           2606    16479    kelas_ajar kelas_ajar_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.kelas_ajar
    ADD CONSTRAINT kelas_ajar_pkey PRIMARY KEY (id_kelas);
 D   ALTER TABLE ONLY public.kelas_ajar DROP CONSTRAINT kelas_ajar_pkey;
       public            postgres    false    217            n           2606    16491    kuis kuis_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT kuis_pkey PRIMARY KEY (id_kuis);
 8   ALTER TABLE ONLY public.kuis DROP CONSTRAINT kuis_pkey;
       public            postgres    false    221            d           2606    16408    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    215            f           2606    16410    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    215            h           2606    16412    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public            postgres    false    215            o           2606    16480    enrollment id_kelas    FK CONSTRAINT     �   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas) NOT VALID;
 =   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_kelas;
       public          postgres    false    217    218    4714            q           2606    16492    kuis id_kelas    FK CONSTRAINT     x   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas);
 7   ALTER TABLE ONLY public.kuis DROP CONSTRAINT id_kelas;
       public          postgres    false    4714    217    221            p           2606    16438    enrollment id_user    FK CONSTRAINT     q   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_user FOREIGN KEY (id_user) REFERENCES public.users(id);
 <   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_user;
       public          postgres    false    215    218    4710                  x�3�44�4�4541LN2W@ �=... W��         k   x��M,I�M,��NT���Lr9%f$'*x���g��Ѐ��ш0i��<�nH�ih"M��S��3�=8A���fr��H9i����� ���         6   x�3�4�)MO,V0T���h4��GÀ�F햁\���#>��qqq *H��           x�u�MOB1E׼��֤��N�
cD�ua"q�v������}�;u�;�Mnr��Xv�yM�Zq���h�șӵDo�ۏ���-gn���S��Y,!
����0(W��e2��Up�ԕPS`4!����q���z����Ǽ��Ķ:οoZI���ϧ4��_�cKQ����9U�޲�,�iQ��S@�,�1��`�����G������;���[�Gz��qZ���>�hCI�-�d��go�����$�bj����A�ZBt'���[�Ā�Ӱi�/�灜     